package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer creates a Server with a fake AES key and a stub discovery.
func newTestServer(t *testing.T, disc oidcDiscovery) *Server {
	t.Helper()
	s := &Server{
		discovery: disc,
	}
	// Use a known 32-byte key.
	copy(s.cipherKey[:], []byte("test-key-32-bytes-padding-padddd"))
	return s
}

// --- encrypt / decrypt round-trip ---

func TestEncryptDecrypt(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})
	orig := session{Sub: "user1", Email: "u@example.com", Username: "u", AccessToken: "tok"}
	enc, err := s.encrypt(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got session
	if err := s.decrypt(enc, &got); err != nil {
		t.Fatal(err)
	}
	if got.Sub != orig.Sub || got.Email != orig.Email {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
}

func TestDecryptTamperedData(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})
	enc, _ := s.encrypt(session{Sub: "x"})
	// Flip a byte in the middle of the ciphertext.
	b := []byte(enc)
	b[len(b)/2] ^= 0xFF
	var dst session
	if err := s.decrypt(string(b), &dst); err == nil {
		t.Fatal("expected decryption to fail on tampered data")
	}
}

// --- extractGroupsFromClaims ---

func TestExtractGroupsFromClaims_Groups(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"eng", "admin"},
	}
	groups := extractGroupsFromClaims(claims)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].ID != "eng" || groups[1].ID != "admin" {
		t.Fatalf("unexpected groups: %+v", groups)
	}
}

func TestExtractGroupsFromClaims_Roles(t *testing.T) {
	claims := map[string]any{
		"roles": []any{"viewer", "editor"},
	}
	groups := extractGroupsFromClaims(claims)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestExtractGroupsFromClaims_ZitadelProjectRoles(t *testing.T) {
	claims := map[string]any{
		"urn:zitadel:iam:org:project:roles": map[string]any{
			"admin": map[string]any{"org-id": struct{}{}},
			"user":  map[string]any{"org-id": struct{}{}},
		},
	}
	groups := extractGroupsFromClaims(claims)
	if len(groups) != 2 {
		t.Fatalf("expected 2 Zitadel roles, got %d", len(groups))
	}
}

func TestExtractGroupsFromClaims_Deduplication(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"eng"},
		"roles":  []any{"eng", "ops"},
	}
	groups := extractGroupsFromClaims(claims)
	if len(groups) != 2 { // "eng" deduped, "ops" added
		t.Fatalf("expected 2 unique groups, got %d: %+v", len(groups), groups)
	}
}

func TestExtractGroupsFromClaims_Empty(t *testing.T) {
	groups := extractGroupsFromClaims(map[string]any{})
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(groups))
	}
}

// --- handleGetState ---

func TestHandleGetState_MissingCookie(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	sr := serializableRequest{
		Method: http.MethodGet,
		URL:    "/",
		Header: map[string][]string{},
	}
	body, _ := json.Marshal(sr)

	req := httptest.NewRequest(http.MethodPost, "/obot-get-state", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handleGetState(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "record not found") {
		t.Fatalf("expected 'record not found', got: %s", rr.Body.String())
	}
}

func TestHandleGetState_ValidSession(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	sess := session{
		Sub:         "uid-123",
		Email:       "alice@example.com",
		Username:    "alice",
		AccessToken: "at-xyz",
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}
	enc, err := s.encrypt(sess)
	if err != nil {
		t.Fatal(err)
	}

	sr := serializableRequest{
		Method: http.MethodGet,
		URL:    "/",
		Header: map[string][]string{
			"Cookie": {sessionCookieName + "=" + enc},
		},
	}
	body, _ := json.Marshal(sr)

	req := httptest.NewRequest(http.MethodPost, "/obot-get-state", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handleGetState(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var state serializableState
	if err := json.NewDecoder(rr.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if state.User != "uid-123" {
		t.Errorf("unexpected User: %s", state.User)
	}
	if state.Email != "alice@example.com" {
		t.Errorf("unexpected Email: %s", state.Email)
	}
	if state.AccessToken != "at-xyz" {
		t.Errorf("unexpected AccessToken: %s", state.AccessToken)
	}
}

func TestHandleGetState_ExpiredSession(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	sess := session{
		Sub:         "uid-123",
		Email:       "alice@example.com",
		AccessToken: "at-xyz",
		ExpiresAt:   time.Now().Add(-time.Hour).Unix(), // already expired
	}
	enc, _ := s.encrypt(sess)

	sr := serializableRequest{
		Method: http.MethodGet,
		URL:    "/",
		Header: map[string][]string{
			"Cookie": {sessionCookieName + "=" + enc},
		},
	}
	body, _ := json.Marshal(sr)

	req := httptest.NewRequest(http.MethodPost, "/obot-get-state", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handleGetState(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d", rr.Code)
	}
}

// --- handleListUserAuthGroups ---

func TestHandleListUserAuthGroups_CachedGroups(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	// Pre-populate the cache as if the user had logged in.
	groups := []groupEntry{
		{ID: "eng", Name: "Engineering"},
		{ID: "ops", Name: "Operations"},
	}
	s.groupCache.Store("uid-123", groups)

	req := httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader("uid-123"))
	rr := httptest.NewRecorder()
	s.handleListUserAuthGroups(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var got []groupEntry
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(got), got)
	}
	if got[0].ID != "eng" || got[1].ID != "ops" {
		t.Errorf("unexpected group IDs: %+v", got)
	}
}

func TestHandleListUserAuthGroups_NoCache(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	req := httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader("unknown-sub"))
	rr := httptest.NewRecorder()
	s.handleListUserAuthGroups(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (empty array), got %d", rr.Code)
	}

	var got []groupEntry
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty array, got %d entries", len(got))
	}
}

// --- handleListAuthGroups ---

func TestHandleListAuthGroups_Returns404(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	req := httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups", nil)
	rr := httptest.NewRecorder()
	s.handleListAuthGroups(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

// --- handleGetUserInfo ---

func TestHandleGetUserInfo_MissingToken(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{UserinfoEndpoint: "http://idp.example.com/userinfo"})

	req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	rr := httptest.NewRecorder()
	s.handleGetUserInfo(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetUserInfo_ProxiesUserinfo(t *testing.T) {
	// Fake IdP userinfo endpoint.
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"sub":     "uid-123",
			"name":    "Alice Smith",
			"email":   "alice@example.com",
			"picture": "https://example.com/alice.jpg",
		})
	}))
	defer idp.Close()

	s := newTestServer(t, oidcDiscovery{UserinfoEndpoint: idp.URL + "/userinfo"})

	req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rr := httptest.NewRecorder()
	s.handleGetUserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var profile map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if profile["name"] != "Alice Smith" {
		t.Errorf("unexpected name: %s", profile["name"])
	}
	if profile["picture"] != "https://example.com/alice.jpg" {
		t.Errorf("unexpected picture: %s", profile["picture"])
	}
}

// --- handleGetState — group cache warming ---

func TestHandleGetState_WarmsGroupCache(t *testing.T) {
	s := newTestServer(t, oidcDiscovery{})

	groups := []groupEntry{{ID: "eng", Name: "eng"}}
	sess := session{
		Sub:         "uid-warm",
		Email:       "u@example.com",
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
		Groups:      groups,
	}
	enc, _ := s.encrypt(sess)

	sr := serializableRequest{
		Method: http.MethodGet,
		URL:    "/",
		Header: map[string][]string{
			"Cookie": {sessionCookieName + "=" + enc},
		},
	}
	body, _ := json.Marshal(sr)

	req := httptest.NewRequest(http.MethodPost, "/obot-get-state", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handleGetState(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// The cache should be warmed now.
	cached, ok := s.groupCache.Load("uid-warm")
	if !ok {
		t.Fatal("group cache not warmed after handleGetState")
	}
	cachedGroups, _ := cached.([]groupEntry)
	if len(cachedGroups) != 1 || cachedGroups[0].ID != "eng" {
		t.Errorf("unexpected cached groups: %+v", cachedGroups)
	}
}

// --- isHTTPS ---

func TestIsHTTPS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if isHTTPS(req) {
		t.Error("expected false for plain HTTP request")
	}

	req.Header.Set("X-Forwarded-Proto", "https")
	if !isHTTPS(req) {
		t.Error("expected true when X-Forwarded-Proto: https")
	}
}

// --- extractCookie ---

func TestExtractCookie(t *testing.T) {
	header := "session=abc; obot_access_token=xyz; other=123"
	if got := extractCookie(header, "obot_access_token"); got != "xyz" {
		t.Errorf("expected 'xyz', got %q", got)
	}
	if got := extractCookie(header, "missing"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// --- pickUsername ---

func TestPickUsername(t *testing.T) {
	tests := []struct {
		claims map[string]any
		want   string
	}{
		{map[string]any{"preferred_username": "alice"}, "alice"},
		{map[string]any{"nickname": "bob", "name": "Bob Smith"}, "bob"},
		{map[string]any{"email": "c@example.com"}, "c@example.com"},
		{map[string]any{"sub": "xyz"}, "xyz"},
		{map[string]any{}, ""},
	}
	for _, tc := range tests {
		if got := pickUsername(tc.claims); got != tc.want {
			t.Errorf("pickUsername(%v) = %q, want %q", tc.claims, got, tc.want)
		}
	}
}

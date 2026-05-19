// Package oidc implements an Obot auth provider that uses OIDC (OpenID Connect).
// It implements the HTTP protocol expected by the Obot proxy manager:
//
//   - GET  /oauth2/start     — initiate auth flow
//   - GET  /oauth2/callback  — handle IdP callback
//   - GET  /oauth2/sign_out  — clear session
//   - POST /obot-get-state   — return authenticated user state from session cookie
package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "obot_access_token"
	stateCookieName   = "_obot_oidc_state"
	cookieMaxAge      = 60 * 60 * 24 * 7 // 7 days
	stateMaxAge       = 60 * 15           // 15 minutes
)

// Config holds the configuration for the OIDC auth provider.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	CookieSecret string
	// ExternalCallbackURL is the full public callback URL, e.g. https://obot.example.com/oauth2/callback
	ExternalCallbackURL string
}

// oidcDiscovery holds the fields we need from the OIDC discovery document.
type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// session holds per-user session data stored in an encrypted cookie.
type session struct {
	Sub         string `json:"sub"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"` // unix timestamp, 0 means no expiry
}

// stateData holds state data stored in a short-lived cookie.
type stateData struct {
	Nonce string `json:"nonce"`
	Rd    string `json:"rd"`
}

// serializableRequest mirrors proxy.serializableRequest.
type serializableRequest struct {
	Method string              `json:"method"`
	URL    string              `json:"url"`
	Header map[string][]string `json:"header"`
}

// serializableState mirrors proxy.serializableState.
type serializableState struct {
	ExpiresOn         *time.Time `json:"expiresOn"`
	AccessToken       string     `json:"accessToken"`
	PreferredUsername string     `json:"preferredUsername"`
	User              string     `json:"user"`
	Email             string     `json:"email"`
	SetCookies        []string   `json:"setCookies"`
}

// Server is the OIDC auth provider HTTP server.
type Server struct {
	cfg       Config
	oauth2Cfg oauth2.Config
	discovery oidcDiscovery
	cipherKey [32]byte // AES-256 key derived from CookieSecret
}

// New creates a new OIDC server, fetching the OIDC discovery document at creation time.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("ZITADEL_ISSUER_URL, ZITADEL_CLIENT_ID, and ZITADEL_CLIENT_SECRET must all be set")
	}
	if cfg.CookieSecret == "" {
		return nil, fmt.Errorf("OBOT_AUTH_PROVIDER_COOKIE_SECRET must be set")
	}

	// Derive a 32-byte AES key from the cookie secret.
	key := sha256.Sum256([]byte(cfg.CookieSecret))

	disc, err := fetchDiscovery(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed for %s: %w", cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &Server{
		cfg:       cfg,
		discovery: disc,
		cipherKey: key,
		oauth2Cfg: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.ExternalCallbackURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  disc.AuthorizationEndpoint,
				TokenURL: disc.TokenEndpoint,
			},
			Scopes: scopes,
		},
	}, nil
}

// Start starts the HTTP server on the given port (e.g. "10240"), or a random
// localhost port if port is empty. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context, port string) error {
	addr := "127.0.0.1:" + port
	if port == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	serverURL := "http://" + ln.Addr().String()

	mux := http.NewServeMux()
	// GET / is the gptscript daemon health check — must return 200.
	// POST / is called by gptscript after the health check; the response body
	// is used by startProvider as the auth provider URL.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprint(w, serverURL)
		}
	})
	mux.HandleFunc("/oauth2/start", s.handleStart)
	mux.HandleFunc("/oauth2/callback", s.handleCallback)
	mux.HandleFunc("/oauth2/sign_out", s.handleSignOut)
	mux.HandleFunc("/obot-get-state", s.handleGetState)

	srv := &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handleStart redirects the user to the OIDC authorization endpoint.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = "/"
	}

	nonce, err := randomBase64(16)
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	sd := stateData{Nonce: nonce, Rd: rd}
	encrypted, err := s.encrypt(sd)
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    encrypted,
		Path:     "/",
		MaxAge:   stateMaxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https"),
	})

	authURL := s.oauth2Cfg.AuthCodeURL(nonce, oauth2.AccessTypeOnline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles the OIDC authorization code callback.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state via cookie.
	stateCookieVal, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "missing state cookie; please restart login", http.StatusBadRequest)
		return
	}

	var sd stateData
	if err := s.decrypt(stateCookieVal.Value, &sd); err != nil {
		http.Error(w, "invalid state cookie", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != sd.Nonce {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:   stateCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		errMsg := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = r.URL.Query().Get("error")
		}
		http.Error(w, "authorization denied: "+errMsg, http.StatusUnauthorized)
		return
	}

	// Exchange code for tokens.
	token, err := s.oauth2Cfg.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract user info from the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	claims, err := parseIDTokenClaims(rawIDToken)
	if err != nil {
		http.Error(w, "failed to parse id_token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	username := pickUsername(claims)

	sess := session{
		Sub:         sub,
		Email:       email,
		Username:    username,
		AccessToken: token.AccessToken,
	}
	if !token.Expiry.IsZero() {
		sess.ExpiresAt = token.Expiry.Unix()
	}

	encrypted, err := s.encrypt(sess)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encrypted,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https"),
	})

	rd := sd.Rd
	if rd == "" {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

// handleSignOut clears the session cookie and redirects.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

// handleGetState returns the authenticated user state from the session cookie.
func (s *Server) handleGetState(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var sr serializableRequest
	if err := json.Unmarshal(body, &sr); err != nil {
		http.Error(w, "failed to parse request", http.StatusBadRequest)
		return
	}

	// Find the session cookie in the serialized request headers.
	cookieHeader := strings.Join(sr.Header["Cookie"], "; ")
	sessionValue := extractCookie(cookieHeader, sessionCookieName)
	if sessionValue == "" {
		http.Error(w, "record not found", http.StatusInternalServerError)
		return
	}

	var sess session
	if err := s.decrypt(sessionValue, &sess); err != nil {
		http.Error(w, "session ticket cookie failed validation", http.StatusInternalServerError)
		return
	}

	// Check expiry.
	if sess.ExpiresAt != 0 && time.Now().Unix() > sess.ExpiresAt {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	state := serializableState{
		User:              sess.Sub,
		Email:             sess.Email,
		PreferredUsername: sess.Username,
		AccessToken:       sess.AccessToken,
	}
	if sess.ExpiresAt != 0 {
		t := time.Unix(sess.ExpiresAt, 0)
		state.ExpiresOn = &t
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

// --- helpers ---

func fetchDiscovery(ctx context.Context, issuerURL string) (oidcDiscovery, error) {
	wellKnown := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return oidcDiscovery{}, err
	}
	return disc, nil
}

// parseIDTokenClaims decodes the payload of a JWT without verifying the signature.
// Signature verification is implicitly trusted because the token comes directly from the IdP
// over a TLS-secured token exchange — it is not user-supplied.
func parseIDTokenClaims(rawJWT string) (map[string]any, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func pickUsername(claims map[string]any) string {
	for _, key := range []string{"preferred_username", "nickname", "name", "email", "sub"} {
		if v, ok := claims[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func extractCookie(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// encrypt marshals v to JSON and encrypts it with AES-256-GCM.
func (s *Server) encrypt(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.cipherKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts a value produced by encrypt and unmarshals it into dst.
func (s *Server) decrypt(encoded string, dst any) error {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(s.cipherKey[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	if len(data) < gcm.NonceSize() {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(plain, dst)
}

// fetchUserProfile fetches user profile from the OIDC userinfo endpoint.
// This is used by identity.go's fetchProviderGroupLookupID.
func fetchUserProfile(ctx context.Context, providerURL, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, providerURL+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var profile map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// Userinfo wraps fetchUserProfile for use by external callers.
func (s *Server) Userinfo(ctx context.Context, accessToken string) (map[string]any, error) {
	// The userinfo endpoint is at the issuer URL.
	issuer := strings.TrimSuffix(s.cfg.IssuerURL, "/")
	// Try to get userinfo endpoint from discovery (not stored, fetch inline).
	_ = issuer
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/oidc/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExternalCallbackURL constructs the callback URL from the obot server hostname.
func ExternalCallbackURL(hostname string) string {
	return strings.TrimSuffix(hostname, "/") + "/oauth2/callback"
}

// ProviderURL returns the URL where this server's UserInfo endpoint is accessible,
// for use by auth.ContextWithProviderURL.
// This is the issuer URL since userinfo is served from there.
func (s *Server) ProviderURL() string {
	return strings.TrimSuffix(s.cfg.IssuerURL, "/")
}

// validateURL is used to check if a URL is a valid URL that could be used as a redirect.
func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL: %s", rawURL)
	}
	return nil
}

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/obot-platform/obot/pkg/authprovider/oidc"
	"github.com/spf13/cobra"
)

// OIDCProvider is the "obot oidc-provider" sub-command.
// It starts the built-in OIDC auth provider HTTP server, prints its URL to
// stdout (so the GPTScript daemon mechanism can discover it), and blocks until
// the context is cancelled.
type OIDCProvider struct{}

func (o *OIDCProvider) Customize(cmd *cobra.Command) {
	cmd.Use = "oidc-provider"
	cmd.Short = "Start the built-in OIDC auth provider (used internally by the GPTScript daemon)"
	cmd.Hidden = true
}

func (o *OIDCProvider) Run(cmd *cobra.Command, _ []string) error {
	issuerURL := os.Getenv("ZITADEL_ISSUER_URL")
	clientID := os.Getenv("ZITADEL_CLIENT_ID")
	clientSecret := os.Getenv("ZITADEL_CLIENT_SECRET")
	cookieSecret := os.Getenv("OBOT_AUTH_PROVIDER_COOKIE_SECRET")

	hostname := os.Getenv("OBOT_SERVER_HOSTNAME")
	if hostname == "" {
		return fmt.Errorf("OBOT_SERVER_HOSTNAME must be set")
	}

	var scopes []string
	if scopesEnv := os.Getenv("ZITADEL_SCOPES"); scopesEnv != "" {
		for _, s := range strings.Split(scopesEnv, ",") {
			if s = strings.TrimSpace(s); s != "" {
				scopes = append(scopes, s)
			}
		}
	}

	srv, err := oidc.New(cmd.Context(), oidc.Config{
		IssuerURL:           issuerURL,
		ClientID:            clientID,
		ClientSecret:        clientSecret,
		Scopes:              scopes,
		CookieSecret:        cookieSecret,
		ExternalCallbackURL: oidc.ExternalCallbackURL(hostname),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("GPTSCRIPT_PORT")
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	return srv.Start(ctx, port)
}

package credentials

import (
	"net/http"
)

// HeaderInjector injects a static value into a specific header.
// Always overrides any existing value — the agent should never
// control which credentials are used.
type HeaderInjector struct {
	// Header is the HTTP header name (e.g., "Authorization", "x-api-key").
	Header string
	// Value is the full header value (e.g., "Bearer sk-...", "sk-...").
	Value string
}

func (h *HeaderInjector) Inject(req *http.Request) {
	req.Header.Set(h.Header, h.Value)
}

// BearerInjector injects an Authorization: Bearer header with a static token.
// Always overrides — the agent may have a dummy placeholder token.
type BearerInjector struct {
	Token string
}

func (b *BearerInjector) Inject(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+b.Token)
}

// APIKeyInjector injects a key into a custom header (e.g., x-api-key).
// Always overrides — the agent may have a dummy placeholder key.
type APIKeyInjector struct {
	HeaderName string
	Key        string
}

func (a *APIKeyInjector) Inject(req *http.Request) {
	req.Header.Set(a.HeaderName, a.Key)
}

// GitHubTokenInjector injects Authorization: token <pat> for GitHub.
// Always overrides — the agent may have a dummy placeholder token.
type GitHubTokenInjector struct {
	Token string
}

func (g *GitHubTokenInjector) Inject(req *http.Request) {
	req.Header.Set("Authorization", "token "+g.Token)
}

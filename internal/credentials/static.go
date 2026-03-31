package credentials

import (
	"net/http"
)

// HeaderInjector injects a static value into a specific header.
type HeaderInjector struct {
	// Header is the HTTP header name (e.g., "Authorization", "x-api-key").
	Header string
	// Value is the full header value (e.g., "Bearer sk-...", "sk-...").
	Value string
}

// Inject adds the header to the request if not already present.
func (h *HeaderInjector) Inject(req *http.Request) {
	if req.Header.Get(h.Header) != "" {
		return
	}
	req.Header.Set(h.Header, h.Value)
}

// BearerInjector injects an Authorization: Bearer header with a static token.
type BearerInjector struct {
	Token string
}

func (b *BearerInjector) Inject(req *http.Request) {
	if req.Header.Get("Authorization") != "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+b.Token)
}

// APIKeyInjector injects a key into a custom header (e.g., x-api-key).
type APIKeyInjector struct {
	HeaderName string
	Key        string
}

func (a *APIKeyInjector) Inject(req *http.Request) {
	if req.Header.Get(a.HeaderName) != "" {
		return
	}
	req.Header.Set(a.HeaderName, a.Key)
}

// GitHubTokenInjector injects Authorization: token <pat> for GitHub.
type GitHubTokenInjector struct {
	Token string
}

func (g *GitHubTokenInjector) Inject(req *http.Request) {
	if req.Header.Get("Authorization") != "" {
		return
	}
	req.Header.Set("Authorization", "token "+g.Token)
}

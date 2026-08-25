package credentials

import (
	"log"
	"net/http"
)

// validateRequest checks if request is valid for credential injection.
// Returns false if req or req.Header is nil, logging the injector name for debugging.
func validateRequest(req *http.Request, injectorName string) bool {
	if req == nil || req.Header == nil {
		log.Printf("DEFENSIVE_CHECK: %s.Inject called with nil request or Header", injectorName)
		return false
	}
	return true
}

// HeaderInjector injects a static value into a specific header.
// Always overrides any existing value — the agent should never
// control which credentials are used.
type HeaderInjector struct {
	// Header is the HTTP header name (e.g., "Authorization", "x-api-key").
	Header string
	// Value is the full header value (e.g., "Bearer sk-...", "sk-...").
	Value string
}

func (h *HeaderInjector) Inject(req *http.Request) InjectResult {
	if !validateRequest(req, "HeaderInjector") {
		return InjectFailed
	}
	req.Header.Set(h.Header, h.Value)
	return InjectOK
}

// BearerInjector injects an Authorization: Bearer header with a static token.
// It overrides the placeholder token the agent presents, but only when the
// agent actually sent an Authorization header. A request with no Authorization
// header is passed through untouched (InjectNoMatch) so the proxy never
// fabricates auth on an unauthenticated request — e.g. the anonymous
// auto-update fetch to downloads.claude.ai, which shares the .claude.ai route.
type BearerInjector struct {
	Token string
}

func (b *BearerInjector) Inject(req *http.Request) InjectResult {
	if !validateRequest(req, "BearerInjector") {
		return InjectFailed
	}
	if req.Header.Get("Authorization") == "" {
		return InjectNoMatch
	}
	req.Header.Set("Authorization", "Bearer "+b.Token)
	return InjectOK
}

// APIKeyInjector injects a key into a custom header (e.g., x-api-key).
// It overrides the placeholder key the agent presents, but only when the agent
// actually sent that header. A request without the header is passed through
// untouched (InjectNoMatch) so the proxy never fabricates auth on an
// unauthenticated request.
type APIKeyInjector struct {
	HeaderName string
	Key        string
}

func (a *APIKeyInjector) Inject(req *http.Request) InjectResult {
	if !validateRequest(req, "APIKeyInjector") {
		return InjectFailed
	}
	if req.Header.Get(a.HeaderName) == "" {
		return InjectNoMatch
	}
	req.Header.Set(a.HeaderName, a.Key)
	return InjectOK
}

package credentials

import (
	"net/http"
	"net/url"
	"testing"
)

func TestStore_InjectCredentials_ExactDomain(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "github.com",
		Injector:    &BearerInjector{Token: "ghp_test123"},
	})

	req := &http.Request{
		URL:    &url.URL{Host: "github.com"},
		Header: make(http.Header),
	}

	if result := store.InjectCredentials(req); result != InjectOK {
		t.Errorf("should match github.com, got %d", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer ghp_test123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ghp_test123")
	}
}

func TestStore_InjectCredentials_DomainSuffix(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		DomainSuffix: ".openai.com",
		Injector:     &BearerInjector{Token: "sk-test"},
	})

	req := &http.Request{
		URL:    &url.URL{Host: "api.openai.com:443"},
		Header: make(http.Header),
	}

	if result := store.InjectCredentials(req); result != InjectOK {
		t.Errorf("should match api.openai.com via suffix .openai.com, got %d", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-test")
	}
}

func TestStore_InjectCredentials_NoMatch(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "github.com",
		Injector:    &BearerInjector{Token: "ghp_test"},
	})

	req := &http.Request{
		URL:    &url.URL{Host: "evil.com"},
		Header: make(http.Header),
	}

	if result := store.InjectCredentials(req); result != InjectNoMatch {
		t.Errorf("should not match evil.com, got %d", result)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty, got %q", got)
	}
}

func TestStore_InjectCredentials_AlwaysOverrides(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		DomainSuffix: ".openai.com",
		Injector:     &BearerInjector{Token: "proxy-token"},
	})

	req := &http.Request{
		URL:    &url.URL{Host: "api.openai.com"},
		Header: make(http.Header),
	}
	// Agent sets a dummy/placeholder token
	req.Header.Set("Authorization", "Bearer paude-proxy-managed")

	if result := store.InjectCredentials(req); result != InjectOK {
		t.Errorf("should match and inject for api.openai.com, got %d", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer proxy-token" {
		t.Errorf("proxy should override agent's dummy token: got %q, want %q", got, "Bearer proxy-token")
	}
}

func TestAPIKeyInjector(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "sk-ant-test"}

	req := &http.Request{Header: make(http.Header)}
	if inj.Inject(req) != InjectOK {
		t.Error("Inject should return InjectOK")
	}
	if got := req.Header.Get("x-api-key"); got != "sk-ant-test" {
		t.Errorf("x-api-key = %q, want %q", got, "sk-ant-test")
	}

	// Should override existing (agent may have a dummy placeholder)
	req2 := &http.Request{Header: make(http.Header)}
	req2.Header.Set("x-api-key", "paude-proxy-managed")
	if inj.Inject(req2) != InjectOK {
		t.Error("Inject should return InjectOK")
	}
	if got := req2.Header.Get("x-api-key"); got != "sk-ant-test" {
		t.Errorf("should override dummy key: got %q, want %q", got, "sk-ant-test")
	}
}

func TestStore_FirstMatchWins(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "api.openai.com",
		Injector:    &BearerInjector{Token: "exact-token"},
	})
	store.AddRoute(Route{
		DomainSuffix: ".openai.com",
		Injector:     &BearerInjector{Token: "suffix-token"},
	})

	req := &http.Request{
		URL:    &url.URL{Host: "api.openai.com"},
		Header: make(http.Header),
	}

	if result := store.InjectCredentials(req); result != InjectOK {
		t.Errorf("should match and inject for api.openai.com, got %d", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer exact-token" {
		t.Errorf("first match should win: got %q", got)
	}
}

// failingInjector is a mock that always fails injection.
type failingInjector struct{}

func (f *failingInjector) Inject(req *http.Request) InjectResult {
	return InjectFailed
}

func TestStore_InjectCredentials_InjectorFails(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "example.com",
		Injector:    &failingInjector{},
	})

	req := &http.Request{
		URL:    &url.URL{Host: "example.com"},
		Header: make(http.Header),
	}

	if result := store.InjectCredentials(req); result != InjectFailed {
		t.Errorf("should return InjectFailed, got %d", result)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty, got %q", got)
	}
}

// TestStore_InjectCredentials_NilRequest tests defensive nil checks
func TestStore_InjectCredentials_NilRequest(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "example.com",
		Injector:    &BearerInjector{Token: "test-token"},
	})

	if result := store.InjectCredentials(nil); result != InjectNoMatch {
		t.Errorf("nil request should return InjectNoMatch, got %d", result)
	}
}

func TestStore_InjectCredentials_NilURL(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "example.com",
		Injector:    &BearerInjector{Token: "test-token"},
	})

	req := &http.Request{
		URL:    nil,
		Header: make(http.Header),
	}

	if result := store.InjectCredentials(req); result != InjectNoMatch {
		t.Errorf("request with nil URL should return InjectNoMatch, got %d", result)
	}
}

// authRequiredInjector is a mock that always returns InjectAuthRequired.
type authRequiredInjector struct{}

func (n *authRequiredInjector) Inject(req *http.Request) InjectResult {
	return InjectAuthRequired
}

func TestStore_NotReadyRoute_ReturnsAuthRequired(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "chatgpt.com",
		PathPrefix:  "/backend-api",
		Injector:    &authRequiredInjector{},
	})

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Host: "chatgpt.com", Path: "/backend-api/codex/models"},
		Header: make(http.Header),
	}
	if result := store.InjectCredentials(req); result != InjectAuthRequired {
		t.Errorf("not-ready route should return InjectAuthRequired, got %d", result)
	}
}

func TestStore_ChatGPTBackendAPIRouting(t *testing.T) {
	store := NewStore()
	// Route 1: ChatGPT OAuth — path-restricted to /backend-api (mirrors credentials.json)
	store.AddRoute(Route{
		ExactDomain: "chatgpt.com",
		PathPrefix:  "/backend-api",
		Injector:    &HeaderInjector{Header: "X-Route", Value: "chatgpt-oauth"},
	})
	// Route 2: OpenAI Bearer — no path restriction (mirrors credentials.json)
	store.AddRoute(Route{
		ExactDomain: "chatgpt.com",
		Injector:    &HeaderInjector{Header: "X-Route", Value: "openai-bearer"},
	})

	tests := []struct {
		name      string
		path      string
		wantRoute string
	}{
		{"codex responses (regression)", "/backend-api/codex/responses", "chatgpt-oauth"},
		{"wham usage (the fix)", "/backend-api/wham/usage", "chatgpt-oauth"},
		{"wham profiles (the fix)", "/backend-api/wham/profiles/me", "chatgpt-oauth"},
		{"referrals (the fix)", "/backend-api/referrals/invite/eligibility", "chatgpt-oauth"},
		{"non-backend-api falls through", "/v1/some-path", "openai-bearer"},
		{"boundary: backend-apix no match", "/backend-apix/foo", "openai-bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Host: "chatgpt.com", Path: tt.path},
				Header: make(http.Header),
			}
			if result := store.InjectCredentials(req); result != InjectOK {
				t.Fatalf("expected InjectOK for path %s, got %d", tt.path, result)
			}
			if got := req.Header.Get("X-Route"); got != tt.wantRoute {
				t.Errorf("path %s routed to %q, want %q", tt.path, got, tt.wantRoute)
			}
		})
	}
}

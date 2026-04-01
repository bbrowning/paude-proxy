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

	if !store.InjectCredentials(req) {
		t.Error("should match github.com")
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

	if !store.InjectCredentials(req) {
		t.Error("should match api.openai.com via suffix .openai.com")
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

	if store.InjectCredentials(req) {
		t.Error("should not match evil.com")
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

	store.InjectCredentials(req)
	if got := req.Header.Get("Authorization"); got != "Bearer proxy-token" {
		t.Errorf("proxy should override agent's dummy token: got %q, want %q", got, "Bearer proxy-token")
	}
}

func TestAPIKeyInjector(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "sk-ant-test"}

	req := &http.Request{Header: make(http.Header)}
	inj.Inject(req)
	if got := req.Header.Get("x-api-key"); got != "sk-ant-test" {
		t.Errorf("x-api-key = %q, want %q", got, "sk-ant-test")
	}

	// Should override existing (agent may have a dummy placeholder)
	req2 := &http.Request{Header: make(http.Header)}
	req2.Header.Set("x-api-key", "paude-proxy-managed")
	inj.Inject(req2)
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

	store.InjectCredentials(req)
	if got := req.Header.Get("Authorization"); got != "Bearer exact-token" {
		t.Errorf("first match should win: got %q", got)
	}
}

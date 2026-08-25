package credentials

import (
	"net/http"
	"testing"
)

func TestHeaderInjector_NilRequest(t *testing.T) {
	inj := &HeaderInjector{Header: "X-Custom", Value: "test"}

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestHeaderInjector_NilHeader(t *testing.T) {
	inj := &HeaderInjector{Header: "X-Custom", Value: "test"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestBearerInjector_NilRequest(t *testing.T) {
	inj := &BearerInjector{Token: "test-token"}

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestBearerInjector_NilHeader(t *testing.T) {
	inj := &BearerInjector{Token: "test-token"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestAPIKeyInjector_NilRequest(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "test-key"}

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestAPIKeyInjector_NilHeader(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "test-key"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestBearerInjector_AuthPresent_Injects(t *testing.T) {
	inj := &BearerInjector{Token: "real-token"}
	req := &http.Request{Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer "+SyntheticToken)

	if inj.Inject(req) != InjectOK {
		t.Fatal("auth header present should return InjectOK")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer real-token")
	}
}

// TestBearerInjector_NoHeader_PassThrough is the downloads.claude.ai regression
// at the injector level: an anonymous request (no Authorization header) that
// matches a bearer route by domain suffix must be forwarded untouched, never
// given a fabricated token.
func TestBearerInjector_NoHeader_PassThrough(t *testing.T) {
	inj := &BearerInjector{Token: "real-token"}
	req := &http.Request{Header: make(http.Header)}

	if got := inj.Inject(req); got != InjectNoMatch {
		t.Fatalf("no auth header should return InjectNoMatch, got %d", got)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be absent, got %q", got)
	}
}

func TestAPIKeyInjector_AuthPresent_Injects(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "real-key"}
	req := &http.Request{Header: make(http.Header)}
	req.Header.Set("x-api-key", SyntheticToken)

	if inj.Inject(req) != InjectOK {
		t.Fatal("api-key header present should return InjectOK")
	}
	if got := req.Header.Get("x-api-key"); got != "real-key" {
		t.Errorf("x-api-key = %q, want %q", got, "real-key")
	}
}

func TestAPIKeyInjector_NoHeader_PassThrough(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "real-key"}
	req := &http.Request{Header: make(http.Header)}

	if got := inj.Inject(req); got != InjectNoMatch {
		t.Fatalf("no x-api-key header should return InjectNoMatch, got %d", got)
	}
	if got := req.Header.Get("x-api-key"); got != "" {
		t.Errorf("x-api-key should be absent, got %q", got)
	}
}

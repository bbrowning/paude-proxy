package credentials

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestGCloudInjector_NilRequest(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestGCloudInjector_NilHeader(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestGCloudInjector_InitFailure(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	req := &http.Request{
		Header: make(http.Header),
	}

	if inj.Inject(req) == InjectOK {
		t.Error("inject should fail when ADC file doesn't exist")
	}

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty on init failure, got %q", got)
	}
}

func TestGCloudInjectorFromJSON_NilRequest(t *testing.T) {
	inj := NewGCloudInjectorFromJSON([]byte("invalid json"))

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestGCloudInjectorFromJSON_NilHeader(t *testing.T) {
	inj := NewGCloudInjectorFromJSON([]byte("invalid json"))

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestGCloudInjector_NeverReturnsInjectAuthRequired(t *testing.T) {
	tests := []struct {
		name     string
		injector *GCloudInjector
		req      *http.Request
	}{
		{
			name:     "nil request",
			injector: NewGCloudInjector("/nonexistent/path"),
			req:      nil,
		},
		{
			name:     "init failure from bad path",
			injector: NewGCloudInjector("/nonexistent/path"),
			req:      &http.Request{Header: make(http.Header)},
		},
		{
			name:     "init failure from invalid JSON",
			injector: NewGCloudInjectorFromJSON([]byte("not valid json")),
			req:      &http.Request{Header: make(http.Header)},
		},
		{
			name:     "init failure from empty JSON",
			injector: NewGCloudInjectorFromJSON([]byte("{}")),
			req:      &http.Request{Header: make(http.Header)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.injector.Inject(tt.req)
			if result == InjectAuthRequired {
				t.Error("GCloudInjector must never return InjectAuthRequired — only ChatGPTInjector should")
			}
			if result != InjectFailed {
				t.Errorf("expected InjectFailed, got %d", result)
			}
		})
	}
}

// validAuthorizedUserADC is a syntactically valid (but unusable — the
// refresh token isn't real) authorized_user ADC JSON blob, sufficient for
// google.CredentialsFromJSON to succeed at parsing/building a Credentials
// object without making any network call.
const validAuthorizedUserADC = `{
	"type": "authorized_user",
	"client_id": "test-client-id",
	"client_secret": "test-client-secret",
	"refresh_token": "test-refresh-token"
}`

func TestGCloudInjector_ForceRefresh_RebuildsCredentials(t *testing.T) {
	inj := NewGCloudInjectorFromJSON([]byte(validAuthorizedUserADC))

	if err := inj.init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	before := inj.credentials

	if err := inj.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	after := inj.credentials

	if before == after {
		t.Error("ForceRefresh should rebuild credentials from the original ADC source, not reuse the cached object")
	}
}

func TestGCloudInjector_ForceRefresh_BeforeInit(t *testing.T) {
	// ForceRefresh must work even if Inject/init was never called yet.
	inj := NewGCloudInjectorFromJSON([]byte(validAuthorizedUserADC))

	if err := inj.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if inj.credentials == nil {
		t.Error("ForceRefresh should populate credentials")
	}
}

func TestGCloudInjector_ForceRefresh_PropagatesInitFailure(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	if err := inj.ForceRefresh(); err == nil {
		t.Error("ForceRefresh should fail when the ADC file doesn't exist")
	}
}

// A ForceRefresh that fails to rebuild (e.g. a transient ADC file read error
// during a host suspend/resume hiccup) must not poison an already-initialized
// injector. Before the fix, doInit set initErr and left initialized=true, so
// every subsequent Inject returned failure -> 502 forever, and since a 502
// (not a 401) never re-triggers the retry path, the injector could never
// recover without a full process restart — the exact outage the retry feature
// exists to prevent.
func TestGCloudInjector_ForceRefresh_FailurePreservesCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adc.json")
	if err := os.WriteFile(path, []byte(validAuthorizedUserADC), 0600); err != nil {
		t.Fatal(err)
	}

	inj := NewGCloudInjector(path)
	if err := inj.init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	good := inj.credentials
	if good == nil {
		t.Fatal("expected credentials after successful init")
	}

	// Simulate the ADC source becoming momentarily unreadable.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// ForceRefresh can't rebuild, so it reports the error (so the caller skips
	// the now-pointless retry)...
	if err := inj.ForceRefresh(); err == nil {
		t.Error("ForceRefresh should report an error when the ADC source is unreadable")
	}

	// ...but it must NOT discard the last-good credentials or poison the
	// injector: the object is unchanged and init() still succeeds.
	if inj.credentials != good {
		t.Error("failed ForceRefresh must preserve the last-good credentials")
	}
	if err := inj.init(); err != nil {
		t.Errorf("init should still succeed after a failed ForceRefresh, got %v", err)
	}
}

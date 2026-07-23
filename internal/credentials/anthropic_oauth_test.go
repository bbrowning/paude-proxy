package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAnthropicCreds(t *testing.T, dir, access, refresh string, expiresAtMs int64) string {
	t.Helper()
	return writeAnthropicCredsWithFields(t, dir, anthropicOAuthTokens{
		AccessToken: access, RefreshToken: refresh, ExpiresAt: expiresAtMs,
	})
}

func writeAnthropicCredsWithFields(t *testing.T, dir string, tokens anthropicOAuthTokens) string {
	t.Helper()
	path := filepath.Join(dir, ".credentials.json")
	data, err := json.Marshal(map[string]any{"claudeAiOauth": tokens})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type anthropicTokenTransport struct {
	base     http.RoundTripper
	endpoint *url.URL
}

func (tr anthropicTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != anthropicTokenURL {
		return nil, errors.New("Anthropic refresh used an unexpected token endpoint")
	}
	clone := req.Clone(req.Context())
	clone.URL = tr.endpoint
	clone.Host = tr.endpoint.Host
	return tr.base.RoundTrip(clone)
}

func anthropicTestClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Transport = anthropicTokenTransport{base: client.Transport, endpoint: endpoint}
	return client
}

func TestAnthropicOAuthInject_OverridesAuthHeader(t *testing.T) {
	dir := t.TempDir()
	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	path := writeAnthropicCreds(t, dir, "real-access-token", "real-refresh-token", expiresAt)

	injector := NewAnthropicOAuthInjector(path)
	req := &http.Request{Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer dummy")

	result := injector.Inject(req)
	if result != InjectOK {
		t.Fatalf("Inject() = %d, want InjectOK", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real-access-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer real-access-token")
	}
}

func TestAnthropicOAuthInject_MissingCredsFile(t *testing.T) {
	injector := NewAnthropicOAuthInjector("/nonexistent/path/.credentials.json")

	if !injector.Available() {
		t.Error("Available() should return true when path is configured")
	}

	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectAuthRequired {
		t.Fatalf("Inject() = %d, want InjectAuthRequired for missing file", result)
	}
}

func TestAnthropicOAuthInject_MalformedCredsJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".credentials.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	injector := NewAnthropicOAuthInjector(path)
	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectFailed {
		t.Fatalf("Inject() = %d, want InjectFailed for malformed JSON", result)
	}
}

func TestAnthropicOAuthInject_EmptyTokens(t *testing.T) {
	dir := t.TempDir()
	path := writeAnthropicCreds(t, dir, "access", "", time.Now().Add(time.Hour).UnixMilli())

	injector := NewAnthropicOAuthInjector(path)
	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectAuthRequired {
		t.Fatalf("Inject() = %d, want InjectAuthRequired for empty refresh token", result)
	}
}

func TestAnthropicOAuthInject_MissingClaudeAiOauth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".credentials.json")
	if err := os.WriteFile(path, []byte(`{"otherKey": {}}`), 0600); err != nil {
		t.Fatal(err)
	}

	injector := NewAnthropicOAuthInjector(path)
	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectFailed {
		t.Fatalf("Inject() = %d, want InjectFailed for missing claudeAiOauth", result)
	}
}

func TestAnthropicOAuthRefresh_RefreshesAndPersists(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	expiredAt := now.Add(-time.Minute).UnixMilli()
	path := writeAnthropicCredsWithFields(t, dir, anthropicOAuthTokens{
		AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: expiredAt, ClientID: "test-client-id",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]string
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		if reqBody["grant_type"] != "refresh_token" {
			t.Errorf("grant_type = %q, want %q", reqBody["grant_type"], "refresh_token")
		}
		if reqBody["refresh_token"] != "old-refresh" {
			t.Errorf("refresh_token = %q, want %q", reqBody["refresh_token"], "old-refresh")
		}
		if reqBody["client_id"] != "test-client-id" {
			t.Errorf("client_id = %q, want %q", reqBody["client_id"], "test-client-id")
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath:  path,
		HTTPClient: anthropicTestClient(t, server),
		Now:        func() time.Time { return now },
	})

	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectOK {
		t.Fatalf("Inject() = %d, want InjectOK", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer new-access" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer new-access")
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading persisted file: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(persisted, &doc); err != nil {
		t.Fatalf("parsing persisted file: %v", err)
	}
	var oauth anthropicOAuthTokens
	if err := json.Unmarshal(doc["claudeAiOauth"], &oauth); err != nil {
		t.Fatalf("parsing persisted oauth: %v", err)
	}
	if oauth.AccessToken != "new-access" {
		t.Errorf("persisted accessToken = %q, want %q", oauth.AccessToken, "new-access")
	}
	if oauth.RefreshToken != "new-refresh" {
		t.Errorf("persisted refreshToken = %q, want %q", oauth.RefreshToken, "new-refresh")
	}
}

func TestAnthropicOAuthRefresh_PreservesNonTokenFields(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	expiredAt := now.Add(-time.Minute).UnixMilli()
	path := writeAnthropicCredsWithFields(t, dir, anthropicOAuthTokens{
		AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: expiredAt,
		Scopes: []string{"user:inference", "user:profile"}, SubscriptionType: "claude_pro", ClientID: "test-client-id",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed-access",
			"refresh_token": "refreshed-refresh",
			"expires_in":    7200,
		})
	}))
	defer server.Close()

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath:  path,
		HTTPClient: anthropicTestClient(t, server),
		Now:        func() time.Time { return now },
	})

	req := &http.Request{Header: make(http.Header)}
	if result := injector.Inject(req); result != InjectOK {
		t.Fatalf("Inject() = %d, want InjectOK", result)
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(persisted, &doc); err != nil {
		t.Fatal(err)
	}
	var oauth anthropicOAuthTokens
	if err := json.Unmarshal(doc["claudeAiOauth"], &oauth); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(oauth.Scopes) != fmt.Sprint([]string{"user:inference", "user:profile"}) {
		t.Errorf("scopes = %v, want [user:inference user:profile]", oauth.Scopes)
	}
	if oauth.SubscriptionType != "claude_pro" {
		t.Errorf("subscriptionType = %q, want %q", oauth.SubscriptionType, "claude_pro")
	}
	if oauth.ClientID != "test-client-id" {
		t.Errorf("clientId = %q, want %q", oauth.ClientID, "test-client-id")
	}
}

func TestAnthropicOAuthRefresh_KeepsOldRefreshIfEmpty(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	expiredAt := now.Add(-time.Minute).UnixMilli()
	path := writeAnthropicCredsWithFields(t, dir, anthropicOAuthTokens{
		AccessToken: "old-access", RefreshToken: "keep-this-refresh", ExpiresAt: expiredAt, ClientID: "client-id",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath:  path,
		HTTPClient: anthropicTestClient(t, server),
		Now:        func() time.Time { return now },
	})

	req := &http.Request{Header: make(http.Header)}
	if result := injector.Inject(req); result != InjectOK {
		t.Fatalf("Inject() = %d, want InjectOK", result)
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(persisted, &doc); err != nil {
		t.Fatal(err)
	}
	var oauth anthropicOAuthTokens
	if err := json.Unmarshal(doc["claudeAiOauth"], &oauth); err != nil {
		t.Fatal(err)
	}
	if oauth.RefreshToken != "keep-this-refresh" {
		t.Errorf("refreshToken = %q, want %q (should keep old when new is empty)", oauth.RefreshToken, "keep-this-refresh")
	}
}

func TestAnthropicOAuthRefresh_FailsWithoutClientID(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	expiredAt := now.Add(-time.Minute).UnixMilli()
	path := writeAnthropicCreds(t, dir, "old-access", "old-refresh", expiredAt)

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath: path,
		Now:       func() time.Time { return now },
	})

	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectFailed {
		t.Fatalf("Inject() = %d, want InjectFailed when no client_id available", result)
	}
}

func TestAnthropicOAuthSetClientID(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	expiredAt := now.Add(-time.Minute).UnixMilli()
	path := writeAnthropicCreds(t, dir, "old-access", "old-refresh", expiredAt)

	var capturedClientID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]string
		_ = json.Unmarshal(body, &reqBody)
		capturedClientID = reqBody["client_id"]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath:  path,
		HTTPClient: anthropicTestClient(t, server),
		Now:        func() time.Time { return now },
	})

	injector.SetClientID("captured-client-id")

	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectOK {
		t.Fatalf("Inject() = %d, want InjectOK after SetClientID", result)
	}
	if capturedClientID != "captured-client-id" {
		t.Errorf("client_id sent in refresh = %q, want %q", capturedClientID, "captured-client-id")
	}
}

func TestAnthropicOAuthSetClientID_DoesNotOverrideExisting(t *testing.T) {
	dir := t.TempDir()
	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	writeAnthropicCredsWithFields(t, dir, anthropicOAuthTokens{
		AccessToken: "access", RefreshToken: "refresh", ExpiresAt: expiresAt, ClientID: "original-client",
	})

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath: filepath.Join(dir, ".credentials.json"),
	})
	// Load the file to pick up the clientId
	req := &http.Request{Header: make(http.Header)}
	injector.Inject(req)

	injector.SetClientID("should-not-override")

	injector.mu.Lock()
	got := injector.config.ClientID
	injector.mu.Unlock()
	if got != "original-client" {
		t.Errorf("ClientID = %q, want %q (should not override existing)", got, "original-client")
	}
}

func TestAnthropicOAuthAcceptLoginTokens(t *testing.T) {
	dir := t.TempDir()
	credsPath := filepath.Join(dir, ".credentials.json")
	now := time.Unix(1_700_000_000, 0)

	injector := NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath: credsPath,
		Now:       func() time.Time { return now },
	})

	loginResp, _ := json.Marshal(map[string]any{
		"access_token":  "login-access",
		"refresh_token": "login-refresh",
		"expires_in":    3600,
	})

	if err := injector.AcceptLoginTokens(loginResp); err != nil {
		t.Fatalf("AcceptLoginTokens: %v", err)
	}

	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectOK {
		t.Fatalf("Inject() = %d after AcceptLoginTokens, want InjectOK", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer login-access" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer login-access")
	}

	persisted, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatalf("state file not created: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(persisted, &doc); err != nil {
		t.Fatal(err)
	}
	var oauth anthropicOAuthTokens
	if err := json.Unmarshal(doc["claudeAiOauth"], &oauth); err != nil {
		t.Fatal(err)
	}
	if oauth.AccessToken != "login-access" {
		t.Errorf("persisted accessToken = %q, want %q", oauth.AccessToken, "login-access")
	}
	if oauth.RefreshToken != "login-refresh" {
		t.Errorf("persisted refreshToken = %q, want %q", oauth.RefreshToken, "login-refresh")
	}
}

func TestAnthropicOAuthInject_CredsFileAppearsLater(t *testing.T) {
	dir := t.TempDir()
	credsPath := filepath.Join(dir, ".credentials.json")

	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	injector := NewAnthropicOAuthInjector(credsPath)

	req := &http.Request{Header: make(http.Header)}
	result := injector.Inject(req)
	if result != InjectAuthRequired {
		t.Fatalf("Inject() before file exists = %d, want InjectAuthRequired", result)
	}

	writeAnthropicCreds(t, dir, "late-access", "late-refresh", expiresAt)

	req = &http.Request{Header: make(http.Header)}
	result = injector.Inject(req)
	if result != InjectOK {
		t.Fatalf("Inject() after file appears = %d, want InjectOK", result)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer late-access" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer late-access")
	}
}

func TestAnthropicOAuthAvailable_EmptyPath(t *testing.T) {
	injector := NewAnthropicOAuthInjector("")
	if injector.Available() {
		t.Error("Available() should return false with empty path")
	}
}

func TestAnthropicOAuthInject_NilRequest(t *testing.T) {
	injector := NewAnthropicOAuthInjector("/some/path")
	result := injector.Inject(nil)
	if result != InjectFailed {
		t.Fatalf("Inject(nil) = %d, want InjectFailed", result)
	}
}

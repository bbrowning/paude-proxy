package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func testAuthJSON(accessToken, refreshToken, idToken, accountID string) []byte {
	data := map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"id_token":      idToken,
			"account_id":    accountID,
		},
		"last_refresh": "2026-01-01T00:00:00Z",
	}
	result, _ := json.Marshal(data)
	return result
}

func writePrivateAuth(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

type chatGPTTokenTransport struct {
	base     http.RoundTripper
	endpoint *url.URL
}

func (t chatGPTTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != chatGPTTokenURL {
		return nil, errors.New("ChatGPT refresh used an unexpected token endpoint")
	}
	clone := req.Clone(req.Context())
	clone.URL = t.endpoint
	clone.Host = t.endpoint.Host
	return t.base.RoundTrip(clone)
}

func chatGPTTestClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Transport = chatGPTTokenTransport{base: client.Transport, endpoint: endpoint}
	return client
}

func TestChatGPTAuthParsingAndAccountIDExtraction(t *testing.T) {
	dir := t.TempDir()
	access := testJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	id := testJWT(map[string]any{
		"https://api.openai.com/auth": map[string]string{
			"chatgpt_account_id": "account-from-id-token",
		},
	})
	path := filepath.Join(dir, "auth.json")
	writePrivateAuth(t, path, testAuthJSON(access, "refresh-secret", id, ""))

	injector := NewChatGPTInjector(path, "")
	req := &http.Request{Header: make(http.Header)}
	if injector.Inject(req) != InjectOK {
		t.Fatal("valid ChatGPT auth should inject")
	}
	if req.Header.Get("Authorization") != "Bearer "+access {
		t.Error("access token was not injected")
	}
	if req.Header.Get(chatGPTAccountHeader) != "account-from-id-token" {
		t.Error("account ID was not extracted from the ID token")
	}

	if got := accountIDFromIDToken(id); got != "account-from-id-token" {
		t.Errorf("account ID = %q, want ID-token account", got)
	}
}

func TestChatGPTAuthMalformedMissingAndInsecureFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"malformed":      []byte("not-json"),
		"missing tokens": []byte(`{"auth_mode":"chatgpt"}`),
		"wrong mode":     []byte(`{"auth_mode":"api_key","tokens":{}}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			writePrivateAuth(t, path, data)
			if NewChatGPTInjector(path, "").Available() {
				t.Error("invalid auth should not be available")
			}
		})
	}

	insecure := filepath.Join(dir, "insecure.json")
	writePrivateAuth(t, insecure, testAuthJSON("access", "refresh", "", "account"))
	if err := os.Chmod(insecure, 0644); err != nil {
		t.Fatal(err)
	}
	if NewChatGPTInjector(insecure, "").Available() {
		t.Error("group/world-readable auth should be rejected")
	}
}

func TestChatGPTExpiryDetection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token := testJWT(map[string]any{"exp": now.Add(4 * time.Minute).Unix()})
	if got := jwtExpiry(token); !got.Equal(now.Add(4 * time.Minute)) {
		t.Errorf("expiry = %v, want %v", got, now.Add(4*time.Minute))
	}
	if !jwtExpiry("opaque-token").IsZero() {
		t.Error("opaque token should have no JWT expiry")
	}
}

func TestChatGPTRefreshRotationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "source.json")
	statePath := filepath.Join(dir, "state", "auth.json")
	now := time.Unix(1_700_000_000, 0)
	oldAccess := testJWT(map[string]any{"exp": now.Add(-time.Minute).Unix()})
	newAccess := testJWT(map[string]any{"exp": now.Add(time.Hour).Unix()})
	id := testJWT(map[string]any{"chatgpt_account_id": "account"})
	writePrivateAuth(t, authPath, testAuthJSON(oldAccess, "old-refresh", id, ""))

	var receivedRefresh, receivedGrant, receivedClientID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		receivedRefresh = values.Get("refresh_token")
		receivedGrant = values.Get("grant_type")
		receivedClientID = values.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+newAccess+`","refresh_token":"rotated-refresh","expires_in":3600}`)
	}))
	defer server.Close()

	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		AuthPath:   authPath,
		StatePath:  statePath,
		HTTPClient: chatGPTTestClient(t, server),
		Now:        func() time.Time { return now },
	})
	req := &http.Request{Header: make(http.Header)}
	if injector.Inject(req) != InjectOK {
		t.Fatal("refresh should succeed")
	}
	if receivedRefresh != "old-refresh" {
		t.Error("refresh request did not use the source refresh token")
	}
	if receivedGrant != "refresh_token" || receivedClientID != chatGPTClientID {
		t.Error("refresh request did not use the Codex OAuth grant fields")
	}
	if req.Header.Get("Authorization") != "Bearer "+newAccess {
		t.Error("refreshed access token was not injected")
	}

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("state file was not persisted: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("state permissions = %o, want 600", info.Mode().Perm())
	}
	persisted, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(persisted, []byte("rotated-refresh")) {
		t.Error("rotated refresh token was not persisted")
	}
	if bytes.Contains(persisted, []byte("old-refresh")) {
		t.Error("old refresh token should have been replaced")
	}
}

func TestChatGPTRefreshFailureFailsClosedWithoutLeakingResponse(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	realMarker := "refresh-response-must-not-leak"
	writePrivateAuth(t, authPath, testAuthJSON("expired-access", "refresh-secret", "", "account"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, realMarker, http.StatusUnauthorized)
	}))
	defer server.Close()

	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousWriter)

	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		AuthPath:   authPath,
		HTTPClient: chatGPTTestClient(t, server),
		Now:        time.Now,
	})
	req := &http.Request{Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer agent-dummy")
	if injector.Inject(req) == InjectOK {
		t.Fatal("refresh failure must fail closed")
	}
	if req.Header.Get("Authorization") != "Bearer agent-dummy" {
		t.Error("failed injection should not modify the agent header")
	}
	if logs.Len() > 0 && bytes.Contains(logs.Bytes(), []byte(realMarker)) {
		t.Error("refresh response body leaked into logs")
	}
}

func TestChatGPTConcurrentRefreshesOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	now := time.Unix(1_700_000_000, 0)
	writePrivateAuth(t, authPath, testAuthJSON("expired-access", "refresh-secret", "", "account"))
	newAccess := testJWT(map[string]any{"exp": now.Add(time.Hour).Unix()})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+newAccess+`","expires_in":3600}`)
	}))
	defer server.Close()

	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		AuthPath:   authPath,
		HTTPClient: chatGPTTestClient(t, server),
		Now:        func() time.Time { return now },
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &http.Request{Header: make(http.Header)}
			if injector.Inject(req) != InjectOK {
				t.Error("concurrent injection failed")
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("refresh calls = %d, want 1", got)
	}
}

func TestChatGPTRouteAndHeaderIsolation(t *testing.T) {
	store := NewStore()
	store.AddRoute(Route{
		ExactDomain: "chatgpt.com",
		PathPrefix:  "/backend-api/codex",
		Methods:     map[string]bool{http.MethodPost: true},
		Injector:    &HeaderInjector{Header: "Authorization", Value: "Bearer real"},
	})

	allowed := &http.Request{Method: http.MethodPost, URL: &url.URL{Host: "chatgpt.com", Path: "/backend-api/codex/responses"}, Header: make(http.Header)}
	allowed.Header.Set("Authorization", "Bearer agent-dummy")
	allowed.Header.Set("X-Unrelated", "preserve")
	if result := store.InjectCredentials(allowed); result != InjectOK || allowed.Header.Get("Authorization") != "Bearer real" || allowed.Header.Get("X-Unrelated") != "preserve" {
		t.Error("ChatGPT route did not isolate and override the intended header")
	}

	for _, req := range []*http.Request{
		{Method: http.MethodGet, URL: &url.URL{Host: "chatgpt.com", Path: "/backend-api/codex/responses"}, Header: make(http.Header)},
		{Method: http.MethodPost, URL: &url.URL{Host: "evil-chatgpt.com", Path: "/backend-api/codex/responses"}, Header: make(http.Header)},
		{Method: http.MethodPost, URL: &url.URL{Host: "chatgpt.com", Path: "/v1/responses"}, Header: make(http.Header)},
	} {
		if result := store.InjectCredentials(req); result != InjectNoMatch {
			t.Error("isolated ChatGPT route matched an unintended request")
		}
	}
}

func TestChatGPTTokenVending(t *testing.T) {
	if IsChatGPTTokenExchange(&http.Request{Method: http.MethodGet, URL: &url.URL{Host: "auth.openai.com", Path: "/oauth/token"}}) {
		t.Error("GET must not be treated as token exchange")
	}
	if IsChatGPTTokenExchange(&http.Request{Method: http.MethodPost, URL: &url.URL{Host: "auth.openai.com", Path: "/oauth/other"}}) {
		t.Error("wrong path must not be treated as token exchange")
	}
	vendor := NewChatGPTTokenVendor(nil)
	response := vendor.HandleTokenExchange(&http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Host: "auth.openai.com", Path: "/oauth/token"},
		Body:   io.NopCloser(strings.NewReader("grant_type=refresh_token")),
	})
	if response == nil || response.StatusCode != http.StatusOK {
		t.Fatal("ChatGPT token exchange was not handled")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("paude-proxy-managed-access")) || bytes.Contains(body, []byte("real-access")) {
		t.Error("token vendor response is not synthetic")
	}
}

func TestChatGPTStatePathOnly_NoFileYet(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "auth.json")

	injector := NewChatGPTInjector("", statePath)
	if !injector.Available() {
		t.Fatal("StatePath-only injector should be available even before login completes")
	}

	req := &http.Request{Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer agent-dummy")
	if injector.Inject(req) == InjectOK {
		t.Error("Inject should not succeed when no tokens are loaded yet")
	}
	if req.Header.Get("Authorization") != "Bearer agent-dummy" {
		t.Error("failed injection should not modify the agent header")
	}
}

func TestChatGPTInject_LogsWhenNoTokensLoaded(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "auth.json")

	injector := NewChatGPTInjector("", statePath)
	if !injector.Available() {
		t.Fatal("StatePath-only injector should be available even before login completes")
	}

	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousWriter)

	req := &http.Request{Header: make(http.Header)}
	if injector.Inject(req) == InjectOK {
		t.Error("Inject should not succeed when no tokens are loaded")
	}
	logOutput := logs.String()
	if !strings.Contains(logOutput, "no tokens loaded") {
		t.Errorf("expected 'no tokens loaded' in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "login may be required") {
		t.Errorf("expected 'login may be required' in log, got: %s", logOutput)
	}
}

func TestChatGPTStatePathOnly_FileExists(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "auth.json")
	access := testJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	writePrivateAuth(t, statePath, testAuthJSON(access, "refresh", "", "account"))

	injector := NewChatGPTInjector("", statePath)
	if !injector.Available() {
		t.Fatal("StatePath-only with existing file should be available")
	}

	req := &http.Request{Header: make(http.Header)}
	if injector.Inject(req) != InjectOK {
		t.Fatal("Inject should succeed when StatePath has valid tokens")
	}
	if req.Header.Get("Authorization") != "Bearer "+access {
		t.Error("access token was not injected")
	}
	if req.Header.Get(chatGPTAccountHeader) != "account" {
		t.Error("account ID was not injected")
	}
}

func TestChatGPTAcceptLoginTokens(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "auth.json")
	now := time.Unix(1_700_000_000, 0)
	access := testJWT(map[string]any{
		"exp":                now.Add(time.Hour).Unix(),
		"chatgpt_account_id": "logged-in-account",
	})

	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		StatePath: statePath,
		Now:       func() time.Time { return now },
	})

	if !injector.Available() {
		t.Fatal("StatePath-only injector should be available")
	}
	req := &http.Request{Header: make(http.Header)}
	if injector.Inject(req) == InjectOK {
		t.Error("Inject should not succeed before login")
	}

	loginResp, _ := json.Marshal(map[string]any{
		"access_token":  access,
		"refresh_token": "real-refresh",
		"id_token":      testJWT(map[string]any{"chatgpt_account_id": "logged-in-account"}),
		"expires_in":    3600,
	})
	if err := injector.AcceptLoginTokens(loginResp); err != nil {
		t.Fatalf("AcceptLoginTokens failed: %v", err)
	}

	req2 := &http.Request{Header: make(http.Header)}
	if injector.Inject(req2) != InjectOK {
		t.Fatal("Inject should succeed after AcceptLoginTokens")
	}
	if req2.Header.Get("Authorization") != "Bearer "+access {
		t.Error("access token was not injected after login")
	}
	if req2.Header.Get(chatGPTAccountHeader) != "logged-in-account" {
		t.Error("account ID was not injected after login")
	}

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("state file was not persisted: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("state permissions = %o, want 600", info.Mode().Perm())
	}
	persisted, _ := os.ReadFile(statePath)
	if !bytes.Contains(persisted, []byte("real-refresh")) {
		t.Error("refresh token was not persisted")
	}
}

func TestChatGPTAcceptLoginTokens_Malformed(t *testing.T) {
	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		StatePath: filepath.Join(t.TempDir(), "auth.json"),
		Now:       time.Now,
	})

	cases := map[string][]byte{
		"not json":           []byte("not-json"),
		"missing access":     []byte(`{"refresh_token":"r"}`),
		"missing refresh":    []byte(`{"access_token":"a"}`),
		"missing account_id": []byte(`{"access_token":"opaque","refresh_token":"r"}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := injector.AcceptLoginTokens(body); err == nil {
				t.Error("AcceptLoginTokens should reject malformed input")
			}
		})
	}
}

func TestChatGPTNoCredentialAndNoLogLeakage(t *testing.T) {
	if NewChatGPTInjector("", "").Available() {
		t.Error("missing auth path should be unavailable")
	}
	secret := "secret-value-for-hash-only"
	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousWriter)
	store := NewStore()
	store.AddRoute(Route{ExactDomain: "chatgpt.com", Injector: &ChatGPTInjector{config: ChatGPTOAuthConfig{}}})
	req := &http.Request{URL: &url.URL{Host: "chatgpt.com"}, Header: make(http.Header)}
	if result := store.InjectCredentials(req); result != InjectFailed {
		t.Errorf("unavailable credential should return InjectFailed, got %d", result)
	}
	if strings.Contains(logs.String(), secret) {
		t.Error("secret appeared in credential logs")
	}
}

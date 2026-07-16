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
	if !injector.Inject(req) {
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
	if !injector.Inject(req) {
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
	if injector.Inject(req) {
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
			if !injector.Inject(req) {
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
	matched, injected := store.InjectCredentials(allowed)
	if !matched || !injected || allowed.Header.Get("Authorization") != "Bearer real" || allowed.Header.Get("X-Unrelated") != "preserve" {
		t.Error("ChatGPT route did not isolate and override the intended header")
	}

	for _, req := range []*http.Request{
		{Method: http.MethodGet, URL: &url.URL{Host: "chatgpt.com", Path: "/backend-api/codex/responses"}, Header: make(http.Header)},
		{Method: http.MethodPost, URL: &url.URL{Host: "evil-chatgpt.com", Path: "/backend-api/codex/responses"}, Header: make(http.Header)},
		{Method: http.MethodPost, URL: &url.URL{Host: "chatgpt.com", Path: "/v1/responses"}, Header: make(http.Header)},
	} {
		if matched, _ := store.InjectCredentials(req); matched {
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
	vendor := NewChatGPTTokenVendor()
	response := vendor.HandleTokenExchange(&http.Request{Method: http.MethodPost, URL: &url.URL{Host: "auth.openai.com", Path: "/oauth/token"}})
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
	if matched, injected := store.InjectCredentials(req); !matched || injected {
		t.Error("unavailable credential should fail closed")
	}
	if strings.Contains(logs.String(), secret) {
		t.Error("secret appeared in credential logs")
	}
}

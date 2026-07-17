package credentials

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsTokenExchange_NilRequest(t *testing.T) {
	// Should handle nil request gracefully
	if IsTokenExchange(nil) {
		t.Error("nil request should return false")
	}
}

func TestIsTokenExchange_NilURL(t *testing.T) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    nil,
	}

	if IsTokenExchange(req) {
		t.Error("request with nil URL should return false")
	}
}

func TestIsTokenExchange_ValidRequest(t *testing.T) {
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Host: "oauth2.googleapis.com",
			Path: "/token",
		},
	}

	if !IsTokenExchange(req) {
		t.Error("valid token exchange request should return true")
	}
}

func TestHandleTokenExchange_NilRequest(t *testing.T) {
	tv := NewTokenVendor()

	resp := tv.HandleTokenExchange(nil)
	if resp == nil {
		t.Fatal("should not return nil response")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleTokenExchange_NilURL(t *testing.T) {
	tv := NewTokenVendor()

	req := &http.Request{
		URL: nil,
	}

	resp := tv.HandleTokenExchange(req)
	if resp == nil {
		t.Fatal("should not return nil response")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleTokenExchange_ValidRequest(t *testing.T) {
	tv := NewTokenVendor()

	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Host: "oauth2.googleapis.com",
			Path: "/token",
		},
	}

	resp := tv.HandleTokenExchange(req)
	if resp == nil {
		t.Fatal("should not return nil response")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify response body contains dummy token
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	defer resp.Body.Close()

	bodyStr := string(body)
	if bodyStr == "" {
		t.Error("response body should not be empty")
	}
	// Should contain the dummy token
	if len(bodyStr) < 10 {
		t.Errorf("response body suspiciously short: %q", bodyStr)
	}
}

func TestChatGPTTokenVendor_RefreshToken_ReturnsSynthetic(t *testing.T) {
	vendor := NewChatGPTTokenVendor(nil)
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Host: "auth.openai.com", Path: "/oauth/token"},
		Body:   io.NopCloser(strings.NewReader("grant_type=refresh_token&refresh_token=dummy")),
	}
	resp := vendor.HandleTokenExchange(req)
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatal("refresh_token grant should return synthetic response")
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("paude-proxy-managed-access")) {
		t.Error("response should contain synthetic access token")
	}
}

func TestChatGPTTokenVendor_LoginExchange_ForwardsAndPersists(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "auth.json")
	now := time.Unix(1_700_000_000, 0)
	realAccess := testJWT(map[string]any{
		"exp":                now.Add(time.Hour).Unix(),
		"chatgpt_account_id": "real-account",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		if values.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type forwarded: %s", values.Get("grant_type"))
		}
		if values.Get("device_code") != "test-code" {
			t.Errorf("device_code = %q, want %q", values.Get("device_code"), "test-code")
		}
		if values.Get("client_id") != chatGPTClientID {
			t.Errorf("client_id = %q, want %q", values.Get("client_id"), chatGPTClientID)
		}
		if values.Get("audience") != "" {
			t.Error("disallowed parameter 'audience' was not stripped")
		}
		if values.Get("scope") != "" {
			t.Error("disallowed parameter 'scope' was not stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  realAccess,
			"refresh_token": "real-refresh",
			"id_token":      testJWT(map[string]any{"chatgpt_account_id": "real-account"}),
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		StatePath:  statePath,
		HTTPClient: chatGPTTestClient(t, server),
		Now:        func() time.Time { return now },
	})

	vendor := NewChatGPTTokenVendor(injector)
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Host: "auth.openai.com", Path: "/oauth/token"},
		Body:   io.NopCloser(strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=test-code&audience=evil&scope=admin&client_id=wrong-client")),
	}
	resp := vendor.HandleTokenExchange(req)
	if resp == nil {
		t.Fatal("login exchange should return a response")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login exchange status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("paude-proxy-managed-access")) {
		t.Error("agent should receive synthetic access token")
	}
	if bytes.Contains(body, []byte(realAccess)) {
		t.Error("agent should NOT receive real access token")
	}
	if bytes.Contains(body, []byte("real-refresh")) {
		t.Error("agent should NOT receive real refresh token")
	}

	persisted, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state file was not persisted: %v", err)
	}
	if !bytes.Contains(persisted, []byte("real-refresh")) {
		t.Error("real refresh token was not persisted to state file")
	}

	injectReq := &http.Request{Header: make(http.Header)}
	if !injector.Inject(injectReq) {
		t.Fatal("Inject should succeed after login exchange")
	}
	if injectReq.Header.Get("Authorization") != "Bearer "+realAccess {
		t.Error("injected access token does not match login exchange result")
	}
}

func TestChatGPTTokenVendor_LoginExchange_UpstreamError_PassesThrough(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "auth.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		if values.Get("audience") != "" {
			t.Error("disallowed parameter 'audience' reached upstream")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "authorization_pending",
			"error_description": "The user has not yet completed authorization",
		})
	}))
	defer server.Close()

	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		StatePath:  statePath,
		HTTPClient: chatGPTTestClient(t, server),
		Now:        time.Now,
	})

	vendor := NewChatGPTTokenVendor(injector)
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Host: "auth.openai.com", Path: "/oauth/token"},
		Body:   io.NopCloser(strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=test&audience=evil")),
	}
	resp := vendor.HandleTokenExchange(req)
	if resp == nil {
		t.Fatal("should return a response")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("upstream error status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("authorization_pending")) {
		t.Error("upstream error body should be passed through to agent")
	}

	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("state file should not be created on upstream error")
	}
}

func TestChatGPTTokenVendor_LoginExchange_RejectsUnknownGrantType(t *testing.T) {
	injector := NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		StatePath: filepath.Join(t.TempDir(), "auth.json"),
		Now:       time.Now,
	})
	vendor := NewChatGPTTokenVendor(injector)
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Host: "auth.openai.com", Path: "/oauth/token"},
		Body:   io.NopCloser(strings.NewReader("grant_type=custom_evil_grant&param=value")),
	}
	resp := vendor.HandleTokenExchange(req)
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown grant_type should be rejected with 400, got %v", resp)
	}
}

func TestSanitizeLoginForm(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		clientID  string
		wantErr   bool
		wantKeys  []string
		checkVals map[string]string
	}{
		{
			name:    "missing grant_type",
			input:   "device_code=abc",
			wantErr: true,
		},
		{
			name:    "unknown grant_type",
			input:   "grant_type=password&username=admin",
			wantErr: true,
		},
		{
			name:     "device_code strips extras",
			input:    "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=dc1&audience=evil&scope=admin",
			clientID: "test-client",
			wantKeys: []string{"grant_type", "device_code", "client_id"},
			checkVals: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "dc1",
				"client_id":   "test-client",
			},
		},
		{
			name:     "device_code enforces client_id",
			input:    "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=dc1&client_id=agent-evil",
			clientID: "correct-client",
			checkVals: map[string]string{
				"client_id": "correct-client",
			},
		},
		{
			name:     "authorization_code allows PKCE params",
			input:    "grant_type=authorization_code&code=authcode&redirect_uri=http://localhost:1455/callback&code_verifier=verifier&client_id=agent&resource=evil",
			clientID: "real-client",
			wantKeys: []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier"},
			checkVals: map[string]string{
				"code":          "authcode",
				"redirect_uri":  "http://localhost:1455/callback",
				"code_verifier": "verifier",
				"client_id":     "real-client",
			},
		},
		{
			name:     "token-exchange allows exchange params",
			input:    "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=x&requested_token=openai-api-key&subject_token=tok&subject_token_type=urn:ietf:params:oauth:token-type:id_token&audience=evil",
			clientID: "canonical",
			wantKeys: []string{"grant_type", "client_id", "requested_token", "subject_token", "subject_token_type"},
			checkVals: map[string]string{
				"requested_token":    "openai-api-key",
				"subject_token":      "tok",
				"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
				"client_id":          "canonical",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, _ := url.ParseQuery(tc.input)
			result, err := sanitizeLoginForm(vals, tc.clientID)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantKeys != nil {
				for _, key := range tc.wantKeys {
					if result.Get(key) == "" {
						t.Errorf("expected key %q in result", key)
					}
				}
				if len(result) != len(tc.wantKeys) {
					t.Errorf("result has %d keys, want %d: %v", len(result), len(tc.wantKeys), result)
				}
			}
			for key, want := range tc.checkVals {
				if got := result.Get(key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

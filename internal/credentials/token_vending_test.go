package credentials

import (
	"io"
	"net/http"
	"net/url"
	"testing"
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

func TestIsAnthropicTokenExchange(t *testing.T) {
	for _, host := range []string{"console.anthropic.com", "platform.claude.com"} {
		for _, path := range []string{"/v1/oauth/token", "/api/oauth/token"} {
			req, _ := http.NewRequest("POST", "https://"+host+path, nil)
			if !IsAnthropicTokenExchange(req) {
				t.Errorf("IsAnthropicTokenExchange should match %s%s", host, path)
			}
		}
	}
	// non-token path on the same host must NOT match
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/messages", nil)
	if IsAnthropicTokenExchange(req) {
		t.Error("IsAnthropicTokenExchange should not match api.anthropic.com messages")
	}
	// wrong method must NOT match
	req2, _ := http.NewRequest("GET", "https://console.anthropic.com/v1/oauth/token", nil)
	if IsAnthropicTokenExchange(req2) {
		t.Error("IsAnthropicTokenExchange should not match GET to the token endpoint")
	}
	// nil request / nil URL must NOT match
	if IsAnthropicTokenExchange(nil) {
		t.Error("IsAnthropicTokenExchange should return false for nil request")
	}
	if IsAnthropicTokenExchange(&http.Request{Method: http.MethodPost, URL: nil}) {
		t.Error("IsAnthropicTokenExchange should return false for nil URL")
	}
}

func TestIsTokenExchange_AnthropicNotMatched(t *testing.T) {
	// IsTokenExchange now matches Google only; Anthropic hosts must be false.
	for _, host := range []string{"console.anthropic.com", "platform.claude.com"} {
		req, _ := http.NewRequest("POST", "https://"+host+"/v1/oauth/token", nil)
		if IsTokenExchange(req) {
			t.Errorf("IsTokenExchange should no longer match Anthropic host %s", host)
		}
	}
}

func TestHandleTokenExchange_ValidRequest(t *testing.T) {
	tv := NewTokenVendor()

	req := &http.Request{
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

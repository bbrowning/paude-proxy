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

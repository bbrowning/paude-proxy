package proxy

import (
	"encoding/json"
	"testing"
)

func TestRewriteRefreshBody_SwapsRefreshTokenPreservesClientID(t *testing.T) {
	orig := []byte(`{"grant_type":"refresh_token","refresh_token":"dummy","client_id":"abc-123"}`)
	out, ok := rewriteRefreshBody(orig, "real-refresh-token")
	if !ok {
		t.Fatal("expected ok=true for refresh_token grant")
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal rewritten body: %v", err)
	}
	if m["refresh_token"] != "real-refresh-token" {
		t.Errorf("refresh_token = %v, want real-refresh-token", m["refresh_token"])
	}
	if m["client_id"] != "abc-123" {
		t.Errorf("client_id = %v, want abc-123 (must be preserved)", m["client_id"])
	}
	if m["grant_type"] != "refresh_token" {
		t.Errorf("grant_type = %v, want refresh_token (must be preserved)", m["grant_type"])
	}
}

func TestRewriteRefreshBody_IgnoresNonRefresh(t *testing.T) {
	orig := []byte(`{"grant_type":"authorization_code","code":"xyz"}`)
	out, ok := rewriteRefreshBody(orig, "real-refresh-token")
	if ok {
		t.Error("expected ok=false for non-refresh grant")
	}
	if string(out) != string(orig) {
		t.Errorf("body should be unchanged, got %q", out)
	}

	// Invalid JSON also returns ok=false and the original body.
	bad := []byte(`not json`)
	out2, ok2 := rewriteRefreshBody(bad, "real-refresh-token")
	if ok2 {
		t.Error("expected ok=false for invalid JSON")
	}
	if string(out2) != string(bad) {
		t.Errorf("invalid-JSON body should be returned unchanged, got %q", out2)
	}
}

// TestRewriteRefreshBody_AuthCodeGrantNotRewritten documents the contract that
// the request hook relies on: authorization_code grants must return ok=false so
// the hook does NOT set the anthropicRefreshMarker and does NOT intercept the
// response (which would replace a non-refresh response body with a dummy).
func TestRewriteRefreshBody_AuthCodeGrantNotRewritten(t *testing.T) {
	in := []byte(`{"grant_type":"authorization_code","code":"abc","client_id":"cc"}`)
	out, ok := rewriteRefreshBody(in, "sk-ant-ort01-REAL")
	if ok {
		t.Fatal("authorization_code grant must not be treated as a refresh")
	}
	if string(out) != string(in) {
		t.Fatalf("body must be unchanged: %s", out)
	}
}

func TestParseRefreshResponse(t *testing.T) {
	body := []byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"token_type":"Bearer"}`)
	access, refresh, expiresIn, err := parseRefreshResponse(body)
	if err != nil {
		t.Fatalf("parseRefreshResponse: %v", err)
	}
	if access != "new-access" {
		t.Errorf("access = %q, want new-access", access)
	}
	if refresh != "new-refresh" {
		t.Errorf("refresh = %q, want new-refresh", refresh)
	}
	if expiresIn != 3600 {
		t.Errorf("expiresIn = %d, want 3600", expiresIn)
	}

	if _, _, _, err := parseRefreshResponse([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildDummyRefreshResponseBody(t *testing.T) {
	out := buildDummyRefreshResponseBody(1234)
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("unmarshal dummy body: %v", err)
	}
	if r.AccessToken != dummyAccessToken {
		t.Errorf("access_token = %q, want %q", r.AccessToken, dummyAccessToken)
	}
	if r.RefreshToken != dummyRefreshToken {
		t.Errorf("refresh_token = %q, want %q", r.RefreshToken, dummyRefreshToken)
	}
	if r.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", r.TokenType)
	}
	if r.ExpiresIn != 1234 {
		t.Errorf("expires_in = %d, want 1234 (must mirror real value)", r.ExpiresIn)
	}
}

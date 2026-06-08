package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbrowning/paude-proxy/internal/credentials"
)

// TestOAuthRefresh_PiggybackEndToEnd exercises the full refresh-piggyback data
// flow that the goproxy request/response hooks implement, against a real
// AnthropicOAuthInjector (backed by a temp creds file) and a mock upstream that
// behaves like Anthropic's token endpoint.
//
// Integration-test approach: the goproxy MITM TLS machinery is not stood up
// here. Instead this test drives the exact request-rewrite then
// response-capture sequence the two hooks perform (rewriteRefreshBody ->
// forward upstream -> parseRefreshResponse/UpdateFromRefresh ->
// buildDummyRefreshResponseBody), wired to the production injector and a real
// httptest upstream. The individual pure functions are covered by
// oauth_refresh_test.go; this test proves they compose correctly with the
// injector and that the creds file ends up holding the rotated real tokens.
func TestOAuthRefresh_PiggybackEndToEnd(t *testing.T) {
	dir := t.TempDir()
	credsPath := filepath.Join(dir, ".credentials.json")
	// Seed the creds file with the REAL refresh token the proxy will swap in.
	seed := `{"claudeAiOauth":{"accessToken":"old-access","refreshToken":"real-refresh-token","expiresAt":0,"scopes":["user:inference"],"subscriptionType":"pro"}}`
	if err := os.WriteFile(credsPath, []byte(seed), 0600); err != nil {
		t.Fatalf("seed creds: %v", err)
	}
	injector := credentials.NewAnthropicOAuthInjector(credsPath)

	// Mock upstream: captures the forwarded refresh_token, returns rotated tokens.
	var forwardedRefresh string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		if rt, ok := m["refresh_token"].(string); ok {
			forwardedRefresh = rt
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-real-access","refresh_token":"new-real-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer upstream.Close()

	// --- Request-hook logic: the agent POSTs a refresh with the DUMMY token. ---
	agentBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + dummyRefreshToken + `","client_id":"cc-client-id"}`)
	newBody, ok := rewriteRefreshBody(agentBody, injector.CurrentRefreshToken())
	if !ok {
		t.Fatal("rewriteRefreshBody should report a refresh_token grant")
	}

	// Forward the rewritten request to the mock upstream (stand-in for goproxy's transport).
	resp, err := http.Post(upstream.URL+"/v1/oauth/token", "application/json", bytes.NewReader(newBody))
	if err != nil {
		t.Fatalf("forward upstream: %v", err)
	}
	defer resp.Body.Close()

	// Assertion (a): the forwarded refresh carried the REAL refresh token,
	// preserving client_id, and NOT the dummy.
	if forwardedRefresh != "real-refresh-token" {
		t.Errorf("upstream saw refresh_token=%q, want real-refresh-token", forwardedRefresh)
	}
	var sent map[string]any
	_ = json.Unmarshal(newBody, &sent)
	if sent["client_id"] != "cc-client-id" {
		t.Errorf("client_id not preserved through rewrite: %v", sent["client_id"])
	}

	// --- Response-hook logic: capture rotated tokens, hand the agent a dummy. ---
	upstreamBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read upstream body: %v", err)
	}
	access, refresh, expiresIn, perr := parseRefreshResponse(upstreamBody)
	if perr != nil {
		t.Fatalf("parseRefreshResponse: %v", perr)
	}
	if access != "" {
		injector.UpdateFromRefresh(access, refresh, expiresIn)
	}
	agentFacing := buildDummyRefreshResponseBody(expiresIn)

	// Assertion (b): the agent-facing response is the DUMMY (no real token leaks).
	var agentResp map[string]any
	if err := json.Unmarshal(agentFacing, &agentResp); err != nil {
		t.Fatalf("unmarshal agent-facing body: %v", err)
	}
	if agentResp["access_token"] != dummyAccessToken {
		t.Errorf("agent-facing access_token = %v, want dummy %q", agentResp["access_token"], dummyAccessToken)
	}
	if agentResp["refresh_token"] != dummyRefreshToken {
		t.Errorf("agent-facing refresh_token = %v, want dummy %q", agentResp["refresh_token"], dummyRefreshToken)
	}
	if bytes.Contains(agentFacing, []byte("new-real-access")) || bytes.Contains(agentFacing, []byte("new-real-refresh")) {
		t.Error("agent-facing response leaked a real token")
	}
	if agentResp["expires_in"] != float64(3600) {
		t.Errorf("agent-facing expires_in = %v, want 3600 (mirrored)", agentResp["expires_in"])
	}

	// Assertion (c): the injector now serves the new REAL refresh token, and the
	// creds file on disk holds the rotated real tokens.
	if got := injector.CurrentRefreshToken(); got != "new-real-refresh" {
		t.Errorf("injector refresh token = %q, want new-real-refresh", got)
	}
	persisted, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatalf("read persisted creds: %v", err)
	}
	if !bytes.Contains(persisted, []byte("new-real-access")) {
		t.Errorf("creds file missing rotated access token: %s", persisted)
	}
	if !bytes.Contains(persisted, []byte("new-real-refresh")) {
		t.Errorf("creds file missing rotated refresh token: %s", persisted)
	}
	// Non-token fields must be preserved on persist.
	if !bytes.Contains(persisted, []byte("user:inference")) {
		t.Errorf("creds file dropped scopes: %s", persisted)
	}
}

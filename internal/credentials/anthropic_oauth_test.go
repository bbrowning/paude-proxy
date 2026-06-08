package credentials

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCreds(t *testing.T, dir string, access, refresh string, expiresAtMs int64) string {
	t.Helper()
	p := filepath.Join(dir, ".credentials.json")
	// Construct JSON manually to avoid encoding/json import just for this helper.
	body := `{"claudeAiOauth":{"accessToken":"` + access + `","refreshToken":"` + refresh + `","expiresAt":` + itoa(expiresAtMs) + `}}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// itoa converts an int64 to its decimal string representation without importing strconv.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

func TestAnthropicInject_OverridesAuthHeader(t *testing.T) {
	dir := t.TempDir()
	p := writeCreds(t, dir, "sk-ant-oat01-current", "sk-ant-ort01-r", 4102444800000)
	inj := NewAnthropicOAuthInjector(p)
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer dummy")
	if !inj.Inject(req) {
		t.Fatal("Inject returned false")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-ant-oat01-current" {
		t.Fatalf("auth header = %q, want overridden current token", got)
	}
}

// TestAnthropicInject_MissingCredsFile guards that a non-existent credentials
// file causes both Available and Inject to report false.
func TestAnthropicInject_MissingCredsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nonexistent.json")
	inj := NewAnthropicOAuthInjector(p)

	if inj.Available() {
		t.Error("Available() returned true for missing file; want false")
	}
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/messages", nil)
	if inj.Inject(req) {
		t.Error("Inject returned true for missing file; want false")
	}
}

// TestAnthropicInject_MalformedCredsJSON guards that unparseable JSON in the
// credentials file causes both Available and Inject to return false.
func TestAnthropicInject_MalformedCredsJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".credentials.json")
	if err := os.WriteFile(p, []byte("not json{"), 0600); err != nil {
		t.Fatal(err)
	}
	inj := NewAnthropicOAuthInjector(p)

	if inj.Available() {
		t.Error("Available() returned true for malformed JSON; want false")
	}
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/messages", nil)
	if inj.Inject(req) {
		t.Error("Inject returned true for malformed JSON; want false")
	}
}

func TestAnthropic_CurrentRefreshToken(t *testing.T) {
	dir := t.TempDir()
	p := writeCreds(t, dir, "sk-ant-oat01-a", "sk-ant-ort01-r", 4102444800000)
	inj := NewAnthropicOAuthInjector(p)
	if got := inj.CurrentRefreshToken(); got != "sk-ant-ort01-r" {
		t.Fatalf("CurrentRefreshToken=%q", got)
	}
}

func TestAnthropic_UpdateFromRefresh_PersistsAndPreserves(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".credentials.json")
	if err := os.WriteFile(p, []byte(`{"claudeAiOauth":{"accessToken":"old","refreshToken":"oldr","expiresAt":1,"scopes":["user:inference"],"subscriptionType":"max"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	inj := NewAnthropicOAuthInjector(p)
	_ = inj.Available()
	inj.UpdateFromRefresh("sk-ant-oat01-new", "sk-ant-ort01-new", 28800)
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/messages", nil)
	if !inj.Inject(req) || req.Header.Get("Authorization") != "Bearer sk-ant-oat01-new" {
		t.Fatalf("inject after update: %q", req.Header.Get("Authorization"))
	}
	data, _ := os.ReadFile(p)
	s := string(data)
	for _, want := range []string{"sk-ant-oat01-new", "sk-ant-ort01-new", "user:inference", "max"} {
		if !strings.Contains(s, want) {
			t.Errorf("persisted file missing %q: %s", want, s)
		}
	}
}

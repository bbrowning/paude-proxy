package proxy

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLogRefreshDiag_NoTokens(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	logRefreshDiag("console.anthropic.com", "/v1/oauth/token")
	out := buf.String()
	if !strings.Contains(out, "console.anthropic.com") || !strings.Contains(out, "/v1/oauth/token") {
		t.Fatalf("expected endpoint in log: %s", out)
	}
	for _, tok := range []string{"sk-ant-oat01-", "sk-ant-ort01-", "refresh_token", "access_token", "Bearer "} {
		if strings.Contains(out, tok) {
			t.Fatalf("token-related material leaked to log: %q in %s", tok, out)
		}
	}
}

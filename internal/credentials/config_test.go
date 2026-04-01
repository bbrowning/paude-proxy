package credentials

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfig_Valid(t *testing.T) {
	data := []byte(`{
		"credentials": [
			{
				"env_var": "MY_KEY",
				"injector": "bearer",
				"domains": [".example.com"]
			}
		]
	}`)

	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("got %d entries, want 1", len(cfg.Credentials))
	}
	if cfg.Credentials[0].EnvVar != "MY_KEY" {
		t.Errorf("env_var = %q, want %q", cfg.Credentials[0].EnvVar, "MY_KEY")
	}
	if cfg.Credentials[0].InjectorType != "bearer" {
		t.Errorf("injector = %q, want %q", cfg.Credentials[0].InjectorType, "bearer")
	}
	if len(cfg.Credentials[0].Domains) != 1 || cfg.Credentials[0].Domains[0] != ".example.com" {
		t.Errorf("domains = %v, want [.example.com]", cfg.Credentials[0].Domains)
	}
}

func TestParseConfig_AllInjectorTypes(t *testing.T) {
	data := []byte(`{
		"credentials": [
			{"env_var": "A", "injector": "bearer", "domains": [".a.com"]},
			{"env_var": "B", "injector": "api_key", "params": {"header_name": "x-key"}, "domains": [".b.com"]},
			{"env_var": "C", "injector": "github_token", "domains": ["c.com"]},
			{"env_var": "D", "injector": "gcloud", "domains": [".d.com"]}
		]
	}`)

	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Credentials) != 4 {
		t.Fatalf("got %d entries, want 4", len(cfg.Credentials))
	}
}

func TestParseConfig_InvalidJSON(t *testing.T) {
	_, err := ParseConfig([]byte(`{not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseConfig_MissingEnvVar(t *testing.T) {
	data := []byte(`{"credentials": [{"env_var": "", "injector": "bearer", "domains": [".x.com"]}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for empty env_var")
	}
}

func TestParseConfig_InvalidInjectorType(t *testing.T) {
	data := []byte(`{"credentials": [{"env_var": "X", "injector": "magic", "domains": [".x.com"]}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for invalid injector type")
	}
}

func TestParseConfig_NoDomains(t *testing.T) {
	data := []byte(`{"credentials": [{"env_var": "X", "injector": "bearer", "domains": []}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for empty domains")
	}
}

func TestParseConfig_EmptyDomain(t *testing.T) {
	data := []byte(`{"credentials": [{"env_var": "X", "injector": "bearer", "domains": [""]}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for empty domain string")
	}
}

func TestParseConfig_APIKeyMissingHeaderName(t *testing.T) {
	data := []byte(`{"credentials": [{"env_var": "X", "injector": "api_key", "domains": [".x.com"]}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for api_key without header_name")
	}
}

func TestParseConfig_APIKeyEmptyHeaderName(t *testing.T) {
	data := []byte(`{"credentials": [{"env_var": "X", "injector": "api_key", "params": {"header_name": ""}, "domains": [".x.com"]}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for api_key with empty header_name")
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	cfg, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
	if len(cfg.Credentials) != 5 {
		t.Errorf("default config has %d entries, want 5", len(cfg.Credentials))
	}

	// Verify the expected entries are present
	envVars := make(map[string]bool)
	for _, entry := range cfg.Credentials {
		envVars[entry.EnvVar] = true
	}
	for _, expected := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CURSOR_API_KEY", "GH_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"} {
		if !envVars[expected] {
			t.Errorf("default config missing entry for %s", expected)
		}
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	data := []byte(`{"credentials": [{"env_var": "TEST_KEY", "injector": "bearer", "domains": [".test.com"]}]}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("got %d entries, want 1", len(cfg.Credentials))
	}
	if cfg.Credentials[0].EnvVar != "TEST_KEY" {
		t.Errorf("env_var = %q, want %q", cfg.Credentials[0].EnvVar, "TEST_KEY")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/creds.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBuildFromConfig_Bearer(t *testing.T) {
	t.Setenv("TEST_BEARER_KEY", "sk-test-123")

	cfg := &CredentialConfig{
		Credentials: []CredentialEntry{
			{
				EnvVar:       "TEST_BEARER_KEY",
				InjectorType: "bearer",
				Domains:      []string{".openai.com"},
			},
		},
	}

	store, tokenVendor, domainMap := BuildFromConfig(cfg)

	if tokenVendor != nil {
		t.Error("tokenVendor should be nil without gcloud entry")
	}

	if domains, ok := domainMap["TEST_BEARER_KEY"]; !ok {
		t.Error("domain map missing TEST_BEARER_KEY")
	} else if len(domains) != 1 || domains[0] != ".openai.com" {
		t.Errorf("domain map = %v, want [.openai.com]", domains)
	}

	req := &http.Request{
		URL:    &url.URL{Host: "api.openai.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req) {
		t.Error("should match api.openai.com")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test-123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-test-123")
	}
}

func TestBuildFromConfig_APIKey(t *testing.T) {
	t.Setenv("TEST_API_KEY", "sk-ant-test")

	cfg := &CredentialConfig{
		Credentials: []CredentialEntry{
			{
				EnvVar:       "TEST_API_KEY",
				InjectorType: "api_key",
				Params:       map[string]string{"header_name": "x-api-key"},
				Domains:      []string{".anthropic.com"},
			},
		},
	}

	store, _, _ := BuildFromConfig(cfg)

	req := &http.Request{
		URL:    &url.URL{Host: "api.anthropic.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req) {
		t.Error("should match api.anthropic.com")
	}
	if got := req.Header.Get("x-api-key"); got != "sk-ant-test" {
		t.Errorf("x-api-key = %q, want %q", got, "sk-ant-test")
	}
}

func TestBuildFromConfig_GitHubToken(t *testing.T) {
	t.Setenv("TEST_GH_TOKEN", "ghp_test")

	cfg := &CredentialConfig{
		Credentials: []CredentialEntry{
			{
				EnvVar:       "TEST_GH_TOKEN",
				InjectorType: "github_token",
				Domains:      []string{"github.com", "api.github.com", ".githubusercontent.com"},
			},
		},
	}

	store, _, _ := BuildFromConfig(cfg)

	// Test exact domain match
	req := &http.Request{
		URL:    &url.URL{Host: "github.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req) {
		t.Error("should match github.com")
	}
	if got := req.Header.Get("Authorization"); got != "token ghp_test" {
		t.Errorf("Authorization = %q, want %q", got, "token ghp_test")
	}

	// Test suffix domain match
	req2 := &http.Request{
		URL:    &url.URL{Host: "raw.githubusercontent.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req2) {
		t.Error("should match raw.githubusercontent.com")
	}
	if got := req2.Header.Get("Authorization"); got != "token ghp_test" {
		t.Errorf("Authorization = %q, want %q", got, "token ghp_test")
	}
}

func TestBuildFromConfig_MissingEnvVarSkipped(t *testing.T) {
	// Ensure the env var is NOT set
	t.Setenv("DEFINITELY_NOT_SET_12345", "")
	os.Unsetenv("DEFINITELY_NOT_SET_12345")

	cfg := &CredentialConfig{
		Credentials: []CredentialEntry{
			{
				EnvVar:       "DEFINITELY_NOT_SET_12345",
				InjectorType: "bearer",
				Domains:      []string{".example.com"},
			},
		},
	}

	store, _, domainMap := BuildFromConfig(cfg)

	if _, ok := domainMap["DEFINITELY_NOT_SET_12345"]; ok {
		t.Error("domain map should not contain entry for unset env var")
	}

	req := &http.Request{
		URL:    &url.URL{Host: "api.example.com"},
		Header: make(http.Header),
	}
	if store.InjectCredentials(req) {
		t.Error("should not match when env var is unset")
	}
}

func TestBuildFromConfig_MultipleEntries(t *testing.T) {
	t.Setenv("TEST_KEY_A", "key-a")
	t.Setenv("TEST_KEY_B", "key-b")

	cfg := &CredentialConfig{
		Credentials: []CredentialEntry{
			{
				EnvVar:       "TEST_KEY_A",
				InjectorType: "bearer",
				Domains:      []string{".a.com"},
			},
			{
				EnvVar:       "TEST_KEY_B",
				InjectorType: "bearer",
				Domains:      []string{".b.com"},
			},
		},
	}

	store, _, domainMap := BuildFromConfig(cfg)

	if len(domainMap) != 2 {
		t.Errorf("domain map has %d entries, want 2", len(domainMap))
	}

	// First entry matches
	req1 := &http.Request{
		URL:    &url.URL{Host: "api.a.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req1) {
		t.Error("should match api.a.com")
	}
	if got := req1.Header.Get("Authorization"); got != "Bearer key-a" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer key-a")
	}

	// Second entry matches
	req2 := &http.Request{
		URL:    &url.URL{Host: "api.b.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req2) {
		t.Error("should match api.b.com")
	}
	if got := req2.Header.Get("Authorization"); got != "Bearer key-b" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer key-b")
	}
}

func TestBuildFromConfig_ExactAndSuffixDomains(t *testing.T) {
	t.Setenv("TEST_MIX_KEY", "mix-token")

	cfg := &CredentialConfig{
		Credentials: []CredentialEntry{
			{
				EnvVar:       "TEST_MIX_KEY",
				InjectorType: "github_token",
				Domains:      []string{"exact.com", ".suffix.com"},
			},
		},
	}

	store, _, _ := BuildFromConfig(cfg)

	// Exact match
	req1 := &http.Request{
		URL:    &url.URL{Host: "exact.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req1) {
		t.Error("should match exact.com")
	}

	// Suffix match
	req2 := &http.Request{
		URL:    &url.URL{Host: "sub.suffix.com"},
		Header: make(http.Header),
	}
	if !store.InjectCredentials(req2) {
		t.Error("should match sub.suffix.com")
	}

	// No match
	req3 := &http.Request{
		URL:    &url.URL{Host: "other.com"},
		Header: make(http.Header),
	}
	if store.InjectCredentials(req3) {
		t.Error("should not match other.com")
	}
}

package filter

import "testing"

func TestDomainFilter_EmptyAllowsAll(t *testing.T) {
	f := NewDomainFilter("")
	if !f.AllowAll() {
		t.Error("empty domain list should allow all")
	}
	if !f.IsAllowed("anything.example.com") {
		t.Error("should allow any domain when allow-all")
	}
}

func TestDomainFilter_ExactMatch(t *testing.T) {
	f := NewDomainFilter("api.openai.com,github.com")

	tests := []struct {
		host    string
		allowed bool
	}{
		{"api.openai.com", true},
		{"github.com", true},
		{"api.openai.com:443", true},
		{"evil.com", false},
		{"openai.com", false},
		{"sub.api.openai.com", false},
	}

	for _, tt := range tests {
		if got := f.IsAllowed(tt.host); got != tt.allowed {
			t.Errorf("IsAllowed(%q) = %v, want %v", tt.host, got, tt.allowed)
		}
	}
}

func TestDomainFilter_WildcardSuffix(t *testing.T) {
	f := NewDomainFilter(".openai.com,.anthropic.com")

	tests := []struct {
		host    string
		allowed bool
	}{
		{"api.openai.com", true},
		{"openai.com", true}, // bare domain matches .openai.com
		{"sub.api.openai.com", true},
		{"api.anthropic.com", true},
		{"evil.com", false},
		{"notopenai.com", false},
	}

	for _, tt := range tests {
		if got := f.IsAllowed(tt.host); got != tt.allowed {
			t.Errorf("IsAllowed(%q) = %v, want %v", tt.host, got, tt.allowed)
		}
	}
}

func TestDomainFilter_Regex(t *testing.T) {
	f := NewDomainFilter("~aiplatform\\.googleapis\\.com$")

	tests := []struct {
		host    string
		allowed bool
	}{
		{"us-central1-aiplatform.googleapis.com", true},
		{"europe-west4-aiplatform.googleapis.com", true},
		{"aiplatform.googleapis.com", true},
		{"storage.googleapis.com", false},
		{"evil.com", false},
	}

	for _, tt := range tests {
		if got := f.IsAllowed(tt.host); got != tt.allowed {
			t.Errorf("IsAllowed(%q) = %v, want %v", tt.host, got, tt.allowed)
		}
	}
}

func TestDomainFilter_Mixed(t *testing.T) {
	f := NewDomainFilter("github.com,.openai.com,~aiplatform\\.googleapis\\.com$")

	tests := []struct {
		host    string
		allowed bool
	}{
		{"github.com", true},
		{"api.openai.com", true},
		{"us-central1-aiplatform.googleapis.com", true},
		{"storage.googleapis.com", false},
		{"evil.com", false},
	}

	for _, tt := range tests {
		if got := f.IsAllowed(tt.host); got != tt.allowed {
			t.Errorf("IsAllowed(%q) = %v, want %v", tt.host, got, tt.allowed)
		}
	}
}

func TestDomainFilter_CaseInsensitive(t *testing.T) {
	f := NewDomainFilter("GitHub.com,.OpenAI.com")

	// Filter lowercases input but stored values are as-is.
	// The host input is lowercased in IsAllowed.
	if !f.IsAllowed("GITHUB.COM") {
		t.Error("should be case-insensitive for host input")
	}
}

func TestDomainFilter_InvalidRegex(t *testing.T) {
	// Invalid regex should be skipped without panic
	f := NewDomainFilter("~[invalid,github.com")
	if !f.IsAllowed("github.com") {
		t.Error("valid exact domain should still work with invalid regex")
	}
}

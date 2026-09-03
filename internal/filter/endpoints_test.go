package filter

import (
	"strings"
	"testing"
)

func TestEndpointFilter(t *testing.T) {
	f, err := NewEndpointFilter("Example.COM.:8000, [2001:0db8:0:0::1]:4317, [::ffff:192.0.2.1]:9000")
	if err != nil {
		t.Fatalf("NewEndpointFilter: %v", err)
	}

	tests := []struct {
		host    string
		port    int
		allowed bool
	}{
		{"example.com", 8000, true},
		{"EXAMPLE.COM.", 8000, true},
		{"example.com", 8001, false},
		{"other.example.com", 8000, false},
		{"2001:db8::1", 4317, true},
		{"2001:0db8:0:0:0:0:0:1", 4317, true},
		{"192.0.2.1", 9000, true},
	}
	for _, tt := range tests {
		if got := f.IsAllowed(tt.host, tt.port); got != tt.allowed {
			t.Errorf("IsAllowed(%q, %d) = %v, want %v", tt.host, tt.port, got, tt.allowed)
		}
	}

	if got := f.String(); got != "example.com:8000,[2001:db8::1]:4317,192.0.2.1:9000" {
		t.Errorf("String() = %q", got)
	}
}

func TestEndpointFilterEmpty(t *testing.T) {
	f, err := NewEndpointFilter(" , , ")
	if err != nil {
		t.Fatalf("NewEndpointFilter: %v", err)
	}
	if !f.Empty() {
		t.Error("empty configuration should create an empty filter")
	}
}

func TestEndpointFilterSkipsEmptyEntries(t *testing.T) {
	f, err := NewEndpointFilter(", example.com:8000,, [2001:db8::1]:4317, ")
	if err != nil {
		t.Fatalf("NewEndpointFilter: %v", err)
	}
	if got, want := f.String(), "example.com:8000,[2001:db8::1]:4317"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestEndpointFilterAllowsUnderscoreHostnames(t *testing.T) {
	f, err := NewEndpointFilter("API_SERVICE:8000,backend_api.internal:8443")
	if err != nil {
		t.Fatalf("NewEndpointFilter: %v", err)
	}

	for _, test := range []struct {
		host string
		port int
	}{
		{"api_service", 8000},
		{"API_SERVICE.", 8000},
		{"backend_api.internal", 8443},
	} {
		if !f.IsAllowed(test.host, test.port) {
			t.Errorf("IsAllowed(%q, %d) = false, want true", test.host, test.port)
		}
	}
	if f.IsAllowed("other_service", 8000) {
		t.Error("underscore hostname exception must remain destination-scoped")
	}
}

func TestEndpointFilterDisallowedAuthorities(t *testing.T) {
	f, err := NewEndpointFilter("allowed.example:8000,blocked.example:8443,[::1]:4317")
	if err != nil {
		t.Fatalf("NewEndpointFilter: %v", err)
	}
	domains := NewDomainFilter("allowed.example,::1")
	if got, want := strings.Join(f.DisallowedAuthorities(domains), ","), "blocked.example:8443"; got != want {
		t.Errorf("DisallowedAuthorities() = %q, want %q", got, want)
	}
	if got := f.DisallowedAuthorities(NewDomainFilter("")); len(got) != 0 {
		t.Errorf("allow-all domains returned disallowed authorities: %v", got)
	}
}

func TestEndpointFilterRejectsMalformedEntries(t *testing.T) {
	tests := []string{
		"example.com",
		"example.com:",
		"example.com:0",
		"example.com:65536",
		"example.com:+80",
		"http://example.com:8000",
		"user@example.com:8000",
		"example.com:8000/path",
		".example.com:8000",
		"~example:8000",
		"*.example.com:8000",
		"[example.com]:8000",
		"[fe80::1%eth0]:8000",
		"2001:db8::1:8000",
		"192.168.001.001:8000",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := NewEndpointFilter(input); err == nil {
				t.Errorf("NewEndpointFilter(%q) succeeded, want error", input)
			}
		})
	}
}

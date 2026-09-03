package filter

import "testing"

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
	f, err := NewEndpointFilter("  ")
	if err != nil {
		t.Fatalf("NewEndpointFilter: %v", err)
	}
	if !f.Empty() {
		t.Error("empty configuration should create an empty filter")
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
		"example.com:8000,,other.example.com:8000",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := NewEndpointFilter(input); err == nil {
				t.Errorf("NewEndpointFilter(%q) succeeded, want error", input)
			}
		})
	}
}

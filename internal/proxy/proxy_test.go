package proxy

import (
	"os"
	"strings"
	"testing"
)

func TestParseOTELPorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single", "4318", []int{4318}, false},
		{"multiple", "4318,4317,8080", []int{4318, 4317, 8080}, false},
		{"with spaces", " 4318 , 4317 ", []int{4318, 4317}, false},
		{"invalid", "abc", nil, true},
		{"out of range", "99999", nil, true},
		{"zero", "0", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseOTELPorts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOTELPorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("got[%d] = %d, want %d", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestPortFilter(t *testing.T) {
	pf := DefaultPortFilter()

	// Default SSL ports
	if !pf.SSLPorts[443] {
		t.Error("443 should be in SSL ports by default")
	}
	if pf.SSLPorts[8443] {
		t.Error("8443 should not be in SSL ports by default")
	}

	// Default safe ports
	if !pf.SafePorts[80] {
		t.Error("80 should be in safe ports by default")
	}
	if !pf.SafePorts[443] {
		t.Error("443 should be in safe ports by default")
	}
	if pf.SafePorts[8080] {
		t.Error("8080 should not be in safe ports by default")
	}

	// AddPorts
	pf.AddPorts([]int{8443, 4318})
	if !pf.SSLPorts[8443] {
		t.Error("8443 should be in SSL ports after AddPorts")
	}
	if !pf.SafePorts[4318] {
		t.Error("4318 should be in safe ports after AddPorts")
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		host        string
		defaultPort int
		want        int
	}{
		{"example.com:443", 80, 443},
		{"example.com:8080", 80, 8080},
		{"example.com", 80, 80},
		{"example.com", 443, 443},
		{"127.0.0.1:3128", 80, 3128},
		{"example.com:notaport", 80, 80},
	}
	for _, tt := range tests {
		got := extractPort(tt.host, tt.defaultPort)
		if got != tt.want {
			t.Errorf("extractPort(%q, %d) = %d, want %d", tt.host, tt.defaultPort, got, tt.want)
		}
	}
}

func TestBlockedLogger(t *testing.T) {
	tmpFile := t.TempDir() + "/blocked.log"

	bl, err := NewBlockedLogger(tmpFile)
	if err != nil {
		t.Fatalf("NewBlockedLogger: %v", err)
	}
	defer bl.Close()

	bl.Log("10.0.0.1", "CONNECT", "evil.com:443")
	bl.Log("10.0.0.2", "GET", "http://bad.com/path")

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %s", len(lines), string(data))
	}

	// Format: <datetime> <timezone> <client-ip> TCP_DENIED/403 <method> <url> BLOCKED
	// 7 fields. paude's parser reads: parts[0]+" "+parts[1] as timestamp, parts[5] as url.
	for i, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 7 {
			t.Errorf("line %d: expected 7+ fields, got %d: %s", i, len(parts), line)
			continue
		}
		if parts[len(parts)-1] != "BLOCKED" {
			t.Errorf("line %d: expected last field 'BLOCKED', got %q", i, parts[len(parts)-1])
		}
		if parts[3] != "TCP_DENIED/403" {
			t.Errorf("line %d: expected 'TCP_DENIED/403' at index 3, got %q", i, parts[3])
		}
	}

	// Verify specific content
	if !strings.Contains(lines[0], "CONNECT") || !strings.Contains(lines[0], "evil.com:443") {
		t.Errorf("line 0 missing expected content: %s", lines[0])
	}
	if !strings.Contains(lines[1], "GET") || !strings.Contains(lines[1], "http://bad.com/path") {
		t.Errorf("line 1 missing expected content: %s", lines[1])
	}
}

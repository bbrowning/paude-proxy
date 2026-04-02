package proxy

import (
	"net"
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

func TestNewClientFilter(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantErr bool
	}{
		{"empty", "", true, false},
		{"single IP", "10.0.0.1", false, false},
		{"multiple IPs", "10.0.0.1,10.0.0.2", false, false},
		{"CIDR", "10.0.0.0/24", false, false},
		{"mixed", "10.0.0.1,172.16.0.0/12", false, false},
		{"with spaces", " 10.0.0.1 , 10.0.0.2 ", false, false},
		{"hostname", "notanip", false, false}, // treated as DNS hostname, not invalid
		{"invalid CIDR", "10.0.0.0/99", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf, err := NewClientFilter(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClientFilter(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && (cf == nil) != tt.wantNil {
				t.Errorf("NewClientFilter(%q) nil = %v, wantNil %v", tt.input, cf == nil, tt.wantNil)
			}
		})
	}
}

func TestClientFilter_IsAllowed(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		testIP  string
		allowed bool
	}{
		{"exact match", "10.0.0.5", "10.0.0.5", true},
		{"no match", "10.0.0.5", "10.0.0.6", false},
		{"CIDR match", "10.0.0.0/24", "10.0.0.42", true},
		{"CIDR no match", "10.0.0.0/24", "10.0.1.1", false},
		{"multiple IPs match second", "10.0.0.1,10.0.0.2", "10.0.0.2", true},
		{"multiple IPs no match", "10.0.0.1,10.0.0.2", "10.0.0.3", false},
		{"mixed match CIDR", "10.0.0.1,172.16.0.0/12", "172.20.5.3", true},
		{"IPv6 exact", "::1", "::1", true},
		{"IPv6 no match", "::1", "::2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf, err := NewClientFilter(tt.filter)
			if err != nil {
				t.Fatalf("NewClientFilter(%q): %v", tt.filter, err)
			}
			ip := net.ParseIP(tt.testIP)
			if ip == nil {
				t.Fatalf("invalid test IP: %s", tt.testIP)
			}
			got := cf.IsAllowed(ip)
			if got != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.testIP, got, tt.allowed)
			}
		})
	}
}

func TestClientFilter_NilAllowsAll(t *testing.T) {
	var cf *ClientFilter
	if !cf.IsAllowed(net.ParseIP("1.2.3.4")) {
		t.Error("nil ClientFilter should allow all IPs")
	}
}

func TestNewClientFilter_Hostnames(t *testing.T) {
	cf, err := NewClientFilter("localhost")
	if err != nil {
		t.Fatalf("NewClientFilter(\"localhost\") error: %v", err)
	}
	if cf == nil {
		t.Fatal("expected non-nil ClientFilter")
	}
	if len(cf.hostnames) != 1 || cf.hostnames[0] != "localhost" {
		t.Errorf("expected hostnames=[localhost], got %v", cf.hostnames)
	}
	if len(cf.resolved["localhost"]) == 0 {
		t.Error("expected at least one resolved IP for localhost")
	}
}

func TestNewClientFilter_MixedIPsHostnamesCIDRs(t *testing.T) {
	cf, err := NewClientFilter("10.0.0.1,localhost,172.16.0.0/12")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cf.ips) != 1 {
		t.Errorf("expected 1 static IP, got %d", len(cf.ips))
	}
	if len(cf.nets) != 1 {
		t.Errorf("expected 1 CIDR, got %d", len(cf.nets))
	}
	if len(cf.hostnames) != 1 || cf.hostnames[0] != "localhost" {
		t.Errorf("expected hostnames=[localhost], got %v", cf.hostnames)
	}
}

func TestClientFilter_IsAllowed_WithResolvedIPs(t *testing.T) {
	cf := &ClientFilter{
		ips:      []net.IP{net.ParseIP("10.0.0.1")},
		resolved: map[string][]net.IP{"myhost": {net.ParseIP("192.168.1.100")}},
		stopCh:   make(chan struct{}),
	}

	// Static IP should match
	if !cf.IsAllowed(net.ParseIP("10.0.0.1")) {
		t.Error("static IP 10.0.0.1 should be allowed")
	}
	// Resolved IP should match
	if !cf.IsAllowed(net.ParseIP("192.168.1.100")) {
		t.Error("resolved IP 192.168.1.100 should be allowed")
	}
	// Unknown IP should not match
	if cf.IsAllowed(net.ParseIP("10.0.0.2")) {
		t.Error("unknown IP 10.0.0.2 should not be allowed")
	}
}

func TestClientFilter_IsAllowed_Localhost(t *testing.T) {
	cf, err := NewClientFilter("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// localhost should resolve to 127.0.0.1 and/or ::1
	if !cf.IsAllowed(net.ParseIP("127.0.0.1")) && !cf.IsAllowed(net.ParseIP("::1")) {
		t.Error("expected localhost to resolve to 127.0.0.1 or ::1")
	}
}

func TestClientFilter_StopNilSafe(t *testing.T) {
	var cf *ClientFilter
	cf.Stop() // nil — should not panic

	cf2, _ := NewClientFilter("10.0.0.1")
	cf2.Stop() // no hostnames — should not panic
}

func TestClientFilter_StopDoubleCall(t *testing.T) {
	cf, _ := NewClientFilter("localhost")
	cf.StartResolving()
	cf.Stop()
	cf.Stop() // second call — should not panic
}

func TestClientFilter_String_WithHostnames(t *testing.T) {
	cf, err := NewClientFilter("10.0.0.1,localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := cf.String()
	if !strings.Contains(s, "10.0.0.1") {
		t.Errorf("String() should contain static IP, got %q", s)
	}
	if !strings.Contains(s, "localhost") {
		t.Errorf("String() should contain hostname, got %q", s)
	}
	if !strings.Contains(s, "resolved:") {
		t.Errorf("String() should contain resolved IPs for localhost, got %q", s)
	}
}

func TestClientFilter_StartResolving_NilSafe(t *testing.T) {
	// StartResolving on nil should not panic
	var cf *ClientFilter
	cf.StartResolving()
}

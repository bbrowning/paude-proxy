package filter

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// EndpointFilter contains exact destination authorities whose ports are allowed
// as exceptions to the proxy's default port policy. Domain filtering remains a
// separate, mandatory check.
type EndpointFilter struct {
	exact []string
	set   map[string]struct{}
}

// NewEndpointFilter parses a comma-separated list of exact host:port
// authorities. IPv6 addresses must be bracketed.
func NewEndpointFilter(endpointList string) (*EndpointFilter, error) {
	f := &EndpointFilter{set: make(map[string]struct{})}
	if strings.TrimSpace(endpointList) == "" {
		return f, nil
	}

	for _, raw := range strings.Split(endpointList, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, fmt.Errorf("empty endpoint entry")
		}

		authority, err := canonicalAuthority(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint %q: %w", raw, err)
		}
		if _, exists := f.set[authority]; exists {
			continue
		}
		f.set[authority] = struct{}{}
		f.exact = append(f.exact, authority)
	}

	return f, nil
}

// IsAllowed reports whether host and port exactly match a configured endpoint.
func (f *EndpointFilter) IsAllowed(host string, port int) bool {
	if f == nil {
		return false
	}
	canonical, err := canonicalHostname(host)
	if err != nil {
		return false
	}
	_, ok := f.set[net.JoinHostPort(canonical, strconv.Itoa(port))]
	return ok
}

// Empty reports whether no endpoint exceptions are configured.
func (f *EndpointFilter) Empty() bool {
	return f == nil || len(f.exact) == 0
}

func (f *EndpointFilter) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.exact, ",")
}

func canonicalAuthority(authority string) (string, error) {
	if strings.ContainsAny(authority, "/?#@") || strings.Contains(authority, "://") {
		return "", fmt.Errorf("must be an authority without a scheme, path, query, fragment, or userinfo")
	}

	host, portString, err := net.SplitHostPort(authority)
	if err != nil {
		return "", fmt.Errorf("must be in host:port form: %w", err)
	}
	if portString == "" {
		return "", fmt.Errorf("port is required")
	}
	for _, r := range portString {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("port %q must be numeric", portString)
		}
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("port %q must be between 1 and 65535", portString)
	}

	if strings.HasPrefix(authority, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return "", fmt.Errorf("brackets are only valid around IPv6 addresses")
		}
		if addr.Zone() != "" {
			return "", fmt.Errorf("IPv6 zones are not valid destination hosts")
		}
	}
	canonical, err := canonicalHostname(host)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(canonical, strconv.Itoa(port)), nil
}

func canonicalHostname(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("host is required")
	}
	if strings.HasPrefix(host, ".") || strings.HasPrefix(host, "~") || strings.Contains(host, "*") {
		return "", fmt.Errorf("host must be an exact hostname or IP address")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("IPv6 zones are not valid destination hosts")
		}
		return addr.Unmap().String(), nil
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("IPv6 addresses must be bracketed")
	}
	if onlyDigitsAndDots(host) {
		return "", fmt.Errorf("invalid IP address")
	}
	if len(host) > 253 {
		return "", fmt.Errorf("hostname is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid hostname label")
		}
		for i, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0 && i < len(label)-1) {
				continue
			}
			return "", fmt.Errorf("invalid character in hostname")
		}
	}
	return host, nil
}

func onlyDigitsAndDots(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

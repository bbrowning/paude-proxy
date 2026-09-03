package filter

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// ValidateDomainList rejects authority-like entries in ALLOWED_DOMAINS. Port
// exceptions are destination-scoped and belong in ALLOWED_ENDPOINTS instead.
// Regex entries are left untouched because colons can be meaningful regex
// syntax rather than an authority separator.
func ValidateDomainList(domainList string) error {
	for _, raw := range strings.Split(domainList, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" || strings.HasPrefix(entry, "~") {
			continue
		}

		candidate := strings.TrimPrefix(strings.TrimPrefix(entry, "."), "*.")
		if domainPatternHasPort(candidate) {
			return fmt.Errorf("entry %q must not include a port; configure exact host:port exceptions with ALLOWED_ENDPOINTS", entry)
		}
	}
	return nil
}

func domainPatternHasPort(pattern string) bool {
	if _, _, err := net.SplitHostPort(pattern); err == nil {
		return true
	}
	if strings.HasPrefix(pattern, "[") {
		if closing := strings.LastIndex(pattern, "]"); closing >= 0 {
			return len(pattern) > closing+1 && pattern[closing+1] == ':'
		}
	}
	if _, err := netip.ParseAddr(pattern); err == nil {
		return false
	}
	return strings.Contains(pattern, ":")
}

// DomainFilter checks whether a hostname is allowed based on
// an allowlist of exact domains, wildcard suffixes, and regex patterns.
// An empty allowlist means all domains are allowed.
type DomainFilter struct {
	mu       sync.RWMutex
	exact    map[string]bool
	suffixes []string
	regexes  []*regexp.Regexp
	allowAll bool
}

// NewDomainFilter creates a filter from a comma-separated domain list.
// Supports three formats matching paude's domain.py conventions:
//   - Exact domain: "api.example.com"
//   - Wildcard suffix: ".example.com" (matches example.com and *.example.com)
//   - Regex: "~pattern" (matched against the full hostname)
//
// An empty string means allow all domains.
func NewDomainFilter(domainList string) *DomainFilter {
	f := &DomainFilter{
		exact: make(map[string]bool),
	}

	domainList = strings.TrimSpace(domainList)
	if domainList == "" {
		f.allowAll = true
		return f
	}

	for _, d := range strings.Split(domainList, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "~") {
			pattern := strings.ToLower(d[1:])
			re, err := regexp.Compile(pattern)
			if err != nil {
				// Skip invalid regex, log would be better but keep it simple
				continue
			}
			f.regexes = append(f.regexes, re)
		} else if strings.HasPrefix(d, ".") {
			// Wildcard suffix: .example.com matches example.com and *.example.com
			suffix := "." + canonicalDomainHostname(d[1:])
			f.suffixes = append(f.suffixes, suffix)
			// Also match the bare domain (e.g., .example.com matches example.com)
			f.exact[suffix[1:]] = true
		} else {
			f.exact[canonicalDomainHostname(d)] = true
		}
	}

	return f
}

// IsAllowed checks whether the given hostname is permitted.
func (f *DomainFilter) IsAllowed(host string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.allowAll {
		return true
	}

	host = canonicalDomainHostname(host)

	// Check exact match
	if f.exact[host] {
		return true
	}

	// Check wildcard suffixes
	for _, suffix := range f.suffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	// Check regex patterns
	for _, re := range f.regexes {
		if re.MatchString(host) {
			return true
		}
	}

	return false
}

// canonicalDomainHostname normalizes comparison forms without changing the
// permissive ALLOWED_DOMAINS parser contract. Endpoint configuration performs
// stricter validation separately.
func canonicalDomainHostname(host string) string {
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

// AllowAll returns true if the filter permits all domains.
func (f *DomainFilter) AllowAll() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.allowAll
}

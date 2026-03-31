package filter

import (
	"regexp"
	"strings"
	"sync"
)

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
		d = strings.ToLower(d)

		if strings.HasPrefix(d, "~") {
			pattern := d[1:]
			re, err := regexp.Compile(pattern)
			if err != nil {
				// Skip invalid regex, log would be better but keep it simple
				continue
			}
			f.regexes = append(f.regexes, re)
		} else if strings.HasPrefix(d, ".") {
			// Wildcard suffix: .example.com matches example.com and *.example.com
			f.suffixes = append(f.suffixes, d)
			// Also match the bare domain (e.g., .example.com matches example.com)
			f.exact[d[1:]] = true
		} else {
			f.exact[d] = true
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

	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

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

// AllowAll returns true if the filter permits all domains.
func (f *DomainFilter) AllowAll() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.allowAll
}

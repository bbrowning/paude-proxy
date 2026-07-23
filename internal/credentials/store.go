package credentials

import (
	"log"
	"net/http"
	"strings"
	"sync"
)

// SyntheticToken is the dummy access token returned by the token vendor to
// agents. The GCloudInjector checks for this value to detect accidental
// self-proxying (token refresh routing through the proxy's own token vendor).
const SyntheticToken = "paude-proxy-managed"

// InjectResult describes the outcome of a credential injection attempt.
type InjectResult int

const (
	InjectNoMatch      InjectResult = iota // no route matched — pass through
	InjectOK                               // credentials injected — forward to upstream
	InjectFailed                           // injection error — 502 Bad Gateway
	InjectAuthRequired                     // waiting for login — 401 Unauthorized
)

// Injector can inject credentials into an HTTP request.
type Injector interface {
	// Inject adds credential headers to the request.
	Inject(req *http.Request) InjectResult
}

// Route maps a domain pattern to a credential injector.
type Route struct {
	// DomainSuffix matches if the hostname ends with this suffix.
	// Use "." prefix for wildcard (e.g., ".openai.com" matches "api.openai.com").
	// Use exact domain for exact match (e.g., "github.com").
	DomainSuffix string

	// ExactDomain matches the hostname exactly.
	ExactDomain string

	// Injector to use when this route matches.
	Injector Injector

	// PathPrefix optionally restricts this route to a path prefix. A prefix
	// ending in "/" matches all descendants; otherwise the prefix must be
	// followed by "/" or be an exact path.
	PathPrefix string

	// Methods optionally restricts this route to HTTP methods. An empty map
	// allows every method.
	Methods map[string]bool
}

// Store holds credential routes and matches requests to injectors.
type Store struct {
	mu     sync.RWMutex
	routes []Route
}

// NewStore creates an empty credential store.
func NewStore() *Store {
	return &Store{}
}

// AddRoute adds a credential route. Routes are checked in order;
// the first match wins.
func (s *Store) AddRoute(route Route) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = append(s.routes, route)
}

// InjectCredentials finds the first matching route for the request's host
// and injects credentials.
func (s *Store) InjectCredentials(req *http.Request) InjectResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req == nil || req.URL == nil {
		return InjectNoMatch
	}

	host := req.URL.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	for _, route := range s.routes {
		matched := false
		matchedPattern := ""
		pathMatched := route.PathPrefix == "" || pathMatchesPrefix(req.URL.Path, route.PathPrefix)
		methodMatched := len(route.Methods) == 0 || route.Methods[strings.ToUpper(req.Method)]

		if pathMatched && methodMatched && route.ExactDomain != "" && host == route.ExactDomain {
			matched = true
			matchedPattern = route.ExactDomain
		} else if pathMatched && methodMatched && route.DomainSuffix != "" && strings.HasSuffix(host, route.DomainSuffix) {
			matched = true
			matchedPattern = "*" + route.DomainSuffix
		}

		if matched {
			result := route.Injector.Inject(req)
			switch result {
			case InjectOK:
				log.Printf("CREDENTIAL_INJECT host=%s pattern=%s method=%s path=%s", host, matchedPattern, req.Method, req.URL.Path)
			case InjectFailed:
				log.Printf("CREDENTIAL_INJECT_FAILED host=%s pattern=%s method=%s path=%s", host, matchedPattern, req.Method, req.URL.Path)
			case InjectAuthRequired:
				log.Printf("CREDENTIAL_AUTH_REQUIRED host=%s pattern=%s method=%s path=%s", host, matchedPattern, req.Method, req.URL.Path)
			}
			return result
		}
	}

	return InjectNoMatch
}

func pathMatchesPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, prefix+"/")
}

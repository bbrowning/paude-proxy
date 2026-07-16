package credentials

import (
	"log"
	"net/http"
	"strings"
	"sync"
)

// Injector can inject credentials into an HTTP request.
type Injector interface {
	// Inject adds credential headers to the request.
	// Returns true if the credential was successfully set, false on error.
	Inject(req *http.Request) bool
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

// InjectCredentials finds the first matching route for the request's
// host and injects credentials. Returns (matched, injected) where matched
// indicates a route was found and injected indicates the credential was
// successfully set.
func (s *Store) InjectCredentials(req *http.Request) (bool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req == nil || req.URL == nil {
		return false, false
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
			ok := route.Injector.Inject(req)
			if ok {
				log.Printf("CREDENTIAL_INJECT host=%s pattern=%s method=%s path=%s", host, matchedPattern, req.Method, req.URL.Path)
			} else {
				log.Printf("CREDENTIAL_INJECT_FAILED host=%s pattern=%s method=%s path=%s", host, matchedPattern, req.Method, req.URL.Path)
			}
			return true, ok
		}
	}

	return false, false
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

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

	host := req.URL.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	for _, route := range s.routes {
		matched := false
		matchedPattern := ""

		if route.ExactDomain != "" && host == route.ExactDomain {
			matched = true
			matchedPattern = route.ExactDomain
		} else if route.DomainSuffix != "" && strings.HasSuffix(host, route.DomainSuffix) {
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

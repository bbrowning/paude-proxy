package proxy

import "log"

// logRefreshDiag logs only the endpoint of an intercepted OAuth refresh — never
// token values, request/response bodies, or Authorization headers. The proxy
// must never write credentials to logs.
func logRefreshDiag(host, path string) {
	log.Printf("OAUTH_REFRESH host=%s path=%s (rewritten; tokens redacted)", host, path)
}

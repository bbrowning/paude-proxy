package timeouts

import "time"

// HTTP transport timeout constants for handling laptop sleep/wake cycles
// and preventing stale connections.
const (
	// TLSHandshake is the maximum time to wait for a TLS handshake.
	TLSHandshake = 10 * time.Second

	// ResponseHeader is the maximum time to wait for response headers.
	ResponseHeader = 30 * time.Second

	// IdleConn is the maximum time to keep idle connections alive.
	IdleConn = 90 * time.Second
)

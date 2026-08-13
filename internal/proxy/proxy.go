package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/bbrowning/paude-proxy/internal/credentials"
	"github.com/bbrowning/paude-proxy/internal/filter"
	"github.com/bbrowning/paude-proxy/internal/timeouts"
)

// PortFilter controls which ports are allowed for HTTP and CONNECT requests.
type PortFilter struct {
	SafePorts map[int]bool // Allowed for HTTP requests
	SSLPorts  map[int]bool // Allowed for CONNECT requests
}

// DefaultPortFilter returns a PortFilter with squid-compatible defaults.
func DefaultPortFilter() *PortFilter {
	return &PortFilter{
		SafePorts: map[int]bool{80: true, 443: true},
		SSLPorts:  map[int]bool{443: true},
	}
}

// AddPorts adds ports to both SafePorts and SSLPorts.
func (pf *PortFilter) AddPorts(ports []int) {
	for _, p := range ports {
		pf.SafePorts[p] = true
		pf.SSLPorts[p] = true
	}
}

// ParseOTELPorts parses a comma-separated list of port numbers.
func ParseOTELPorts(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port out of range: %d", p)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// BlockedLogger writes blocked-request entries to a log file in the format
// expected by paude's proxy_log.py parser:
//
//	<date> <timezone> <client-ip> <status/code> <method> <url> BLOCKED
type BlockedLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewBlockedLogger opens (or creates) the given path for append-only writing.
func NewBlockedLogger(path string) (*BlockedLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &BlockedLogger{file: f}, nil
}

// Log writes a single blocked-request line.
// Format matches squid's blocked log format that paude's proxy_log.py expects:
//
//	<datetime> <timezone> <client-ip> <status/code> <method> <url> BLOCKED
//
// The datetime field includes both date and time (e.g. "2006-01-02T15:04:05")
// so that parts[0] is datetime, parts[1] is timezone — matching squid's
// 2-field timestamp convention.
func (bl *BlockedLogger) Log(clientIP, method, url string) {
	now := time.Now()
	datetime := now.Format("2006-01-02T15:04:05")
	zone, _ := now.Zone()
	line := fmt.Sprintf("%s %s %s TCP_DENIED/403 %s %s BLOCKED\n", datetime, zone, clientIP, method, url)
	bl.mu.Lock()
	_, _ = bl.file.WriteString(line)
	bl.mu.Unlock()
}

// Close closes the underlying file.
func (bl *BlockedLogger) Close() error {
	return bl.file.Close()
}

// ClientFilter validates client source IPs against an allowlist of IPs, CIDRs,
// and DNS hostnames. Hostnames are resolved to IPs at startup and periodically
// re-resolved in the background (every 30s) to handle dynamic IP assignments
// (e.g., Kubernetes pods restarting). A nil or empty ClientFilter allows all clients.
type ClientFilter struct {
	ips       []net.IP
	nets      []*net.IPNet
	hostnames []string
	resolved  map[string][]net.IP // hostname -> resolved IPs (protected by mu)
	mu        sync.RWMutex
	stopCh    chan struct{}
	stopOnce  sync.Once
}

// NewClientFilter parses a comma-separated list of IPs, CIDRs, and DNS hostnames.
// Returns nil if the input is empty (allow all). Hostnames are resolved immediately;
// resolution failures are logged as warnings (the hostname may become resolvable later).
func NewClientFilter(s string) (*ClientFilter, error) {
	if s == "" {
		return nil, nil
	}
	cf := &ClientFilter{
		stopCh:   make(chan struct{}),
		resolved: make(map[string][]net.IP),
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			_, ipNet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			cf.nets = append(cf.nets, ipNet)
		} else if ip := net.ParseIP(part); ip != nil {
			cf.ips = append(cf.ips, ip)
		} else {
			cf.hostnames = append(cf.hostnames, part)
		}
	}

	if len(cf.hostnames) > 0 {
		cf.resolveHostnames(true)
	}

	return cf, nil
}

// resolveHostnames resolves all configured hostnames and updates the resolved IP map.
// When initialResolve is true, all results are logged. Otherwise, only changes are logged.
func (cf *ClientFilter) resolveHostnames(initialResolve bool) {
	newResolved := make(map[string][]net.IP, len(cf.hostnames))
	for _, hostname := range cf.hostnames {
		addrs, err := net.LookupHost(hostname)
		if err != nil {
			log.Printf("WARNING: failed to resolve allowed client hostname %q: %v", hostname, err)
			continue
		}
		var ips []net.IP
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil {
				ips = append(ips, ip)
			}
		}
		newResolved[hostname] = ips
	}

	cf.mu.Lock()
	old := cf.resolved
	cf.resolved = newResolved
	cf.mu.Unlock()

	for _, hostname := range cf.hostnames {
		newIPs := newResolved[hostname]
		oldIPs := old[hostname]
		if initialResolve || !ipsEqual(newIPs, oldIPs) {
			ipStrs := make([]string, len(newIPs))
			for i, ip := range newIPs {
				ipStrs[i] = ip.String()
			}
			log.Printf("Resolved allowed client hostname %q -> %s", hostname, strings.Join(ipStrs, ", "))
		}
	}
}

// ipsEqual returns true if two IP slices contain the same IPs in the same order.
func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// StartResolving starts a background goroutine that re-resolves all hostname
// entries every 30 seconds to handle pods restarting with new IPs.
func (cf *ClientFilter) StartResolving() {
	if cf == nil || len(cf.hostnames) == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cf.resolveHostnames(false)
			case <-cf.stopCh:
				return
			}
		}
	}()
}

// Stop stops the background hostname re-resolution goroutine. Safe to call multiple times.
func (cf *ClientFilter) Stop() {
	if cf == nil || len(cf.hostnames) == 0 {
		return
	}
	cf.stopOnce.Do(func() { close(cf.stopCh) })
}

func (cf *ClientFilter) IsAllowed(ip net.IP) bool {
	if cf == nil {
		return true
	}
	for _, allowed := range cf.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, ipNet := range cf.nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	cf.mu.RLock()
	resolved := cf.resolved
	cf.mu.RUnlock()
	for _, ips := range resolved {
		for _, allowed := range ips {
			if allowed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func (cf *ClientFilter) String() string {
	if cf == nil {
		return "disabled (all clients allowed)"
	}
	var parts []string
	for _, ip := range cf.ips {
		parts = append(parts, ip.String())
	}
	for _, ipNet := range cf.nets {
		parts = append(parts, ipNet.String())
	}
	if len(cf.hostnames) > 0 {
		cf.mu.RLock()
		resolved := cf.resolved
		cf.mu.RUnlock()
		for _, hostname := range cf.hostnames {
			if ips, ok := resolved[hostname]; ok && len(ips) > 0 {
				ipStrs := make([]string, len(ips))
				for i, ip := range ips {
					ipStrs[i] = ip.String()
				}
				parts = append(parts, fmt.Sprintf("%s (resolved: %s)", hostname, strings.Join(ipStrs, ", ")))
			} else {
				parts = append(parts, fmt.Sprintf("%s (unresolved)", hostname))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// rejectMsg is the generic response body for all rejected requests (CONNECT and plain HTTP).
// Intentionally vague to avoid revealing why the request was blocked.
const rejectMsg = "Request blocked by proxy policy"

// credInjectedFlag is stored in ctx.UserData after successful credential
// injection so the OnResponse handler can log upstream errors for those requests.
type credInjectedFlag struct{}

// Config holds proxy configuration.
type Config struct {
	ListenAddr    string
	CA            *CA
	DomainFilter  *filter.DomainFilter
	CredStore     *credentials.Store
	TokenVendor   *credentials.TokenVendor
	PortFilter    *PortFilter
	BlockedLogger *BlockedLogger
	Verbose       bool
	ClientFilter  *ClientFilter  // If non-nil, only listed IPs/CIDRs can connect
	UpstreamCAs   *x509.CertPool // If non-nil, used as root CAs for upstream TLS verification (for testing)
}

// New creates a configured goproxy server.
func New(cfg Config) *http.Server {
	// DEFENSIVE: Validate required configuration
	if cfg.CA == nil {
		log.Fatal("FATAL: proxy.New called with nil CA - this is a programming error")
	}
	if cfg.DomainFilter == nil {
		log.Fatal("FATAL: proxy.New called with nil DomainFilter - this is a programming error")
	}

	proxy := goproxy.NewProxyHttpServer()
	// Override goproxy's default transport which uses InsecureSkipVerify: true.
	// We MUST verify upstream server TLS certificates to prevent credential theft via MITM.
	proxyTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		IdleConnTimeout:       timeouts.IdleConn,
		TLSHandshakeTimeout:   timeouts.TLSHandshake,
		ResponseHeaderTimeout: timeouts.ResponseHeader,
	}
	if cfg.UpstreamCAs != nil {
		proxyTransport.TLSClientConfig.RootCAs = cfg.UpstreamCAs
	}
	proxy.Tr = proxyTransport
	proxy.Verbose = cfg.Verbose

	// Set up the CA for MITM — use local ConnectAction values instead of
	// goproxy's package-level globals to avoid data races when multiple
	// proxy instances are created concurrently (e.g. in tests).
	tlsCfg := goproxy.TLSConfigFromCA(&cfg.CA.TLSCert)
	mitmConnect := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	rejectConnect := &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsCfg}

	// Handle CONNECT requests: client filter, port filtering, domain filtering, MITM
	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if ctx.Req == nil {
				log.Printf("DEFENSIVE_CHECK: CONNECT handler received nil request for host=%s", host)
				return rejectConnect, host
			}

			// Source IP filtering
			if cfg.ClientFilter != nil {
				srcIP := parseClientIP(ctx)
				if srcIP == nil || !cfg.ClientFilter.IsAllowed(srcIP) {
					log.Printf("CLIENT_REJECTED CONNECT %s from %s (not in allowed clients)", host, clientIP(ctx))
					ctx.Resp = goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusForbidden, rejectMsg)
					return rejectConnect, host
				}
			}

			hostname := stripPort(host)
			port := extractPort(host, 443)

			// Port filtering for CONNECT (SSL_ports)
			if cfg.PortFilter != nil && !cfg.PortFilter.SSLPorts[port] {
				log.Printf("BLOCKED CONNECT %s (port %d not allowed)", host, port)
				if cfg.BlockedLogger != nil {
					cfg.BlockedLogger.Log(clientIP(ctx), "CONNECT", host)
				}
				ctx.Resp = goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusForbidden, rejectMsg)
				return rejectConnect, host
			}

			if !cfg.DomainFilter.IsAllowed(hostname) {
				log.Printf("BLOCKED CONNECT %s", host)
				if cfg.BlockedLogger != nil {
					cfg.BlockedLogger.Log(clientIP(ctx), "CONNECT", host)
				}
				ctx.Resp = goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusForbidden, rejectMsg)
				return rejectConnect, host
			}

			log.Printf("CONNECT %s (MITM)", host)
			return mitmConnect, host
		},
	)

	// Handle all requests (both plain HTTP and MITM'd HTTPS):
	// - Port filtering (Safe_ports)
	// - Intercept OAuth2 token exchanges (return dummy tokens)
	// - Inject credentials based on destination domain
	// - Suppress proxy identity headers
	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if req == nil {
				log.Printf("DEFENSIVE_CHECK: DoFunc received nil request from client=%s", clientIP(ctx))
				return nil, nil
			}
			if req.URL == nil {
				// goproxy doesn't properly reconstruct req.URL from HTTP/2 pseudo-headers in MITM mode.
				// This commonly happens with gRPC clients (e.g., dolt's eventsapi).
				// Log diagnostics and attempt reconstruction from available fields.
				log.Printf("DEFENSIVE_CHECK: DoFunc req.URL is nil - Method=%q Host=%q RequestURI=%q Proto=%q from client=%s",
					req.Method, req.Host, req.RequestURI, req.Proto, clientIP(ctx))

				// Try to reconstruct URL from Host and RequestURI (populated from HTTP/2 pseudo-headers)
				if req.Host != "" && req.RequestURI != "" {
					req.URL = &url.URL{
						Scheme: "https", // MITM tunnel is always HTTPS
						Host:   req.Host,
						Path:   req.RequestURI,
					}
					log.Printf("DEFENSIVE_CHECK: Reconstructed URL from Host+RequestURI: %s", req.URL.String())
				} else {
					log.Printf("DEFENSIVE_CHECK: Cannot reconstruct URL - missing Host or RequestURI")
					return req, goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						http.StatusBadRequest,
						"Malformed request",
					)
				}
			}

			// Source IP filtering for plain HTTP proxy requests.
			// MITM'd HTTPS requests already passed filtering in HandleConnectFunc.
			if cfg.ClientFilter != nil && req.URL.Scheme == "http" {
				srcIP := parseClientIP(ctx)
				if srcIP == nil || !cfg.ClientFilter.IsAllowed(srcIP) {
					log.Printf("CLIENT_REJECTED %s %s from %s (not in allowed clients)", req.Method, req.URL.String(), clientIP(ctx))
					return req, goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						http.StatusForbidden,
						rejectMsg,
					)
				}
			}

			hostname := stripPort(req.URL.Host)

			// Port filtering for HTTP requests (Safe_ports).
			// Only apply to non-CONNECT (plain HTTP) requests — MITM'd
			// HTTPS requests already passed port filtering in HandleConnectFunc.
			if cfg.PortFilter != nil && req.URL.Scheme == "http" {
				port := extractPort(req.URL.Host, 80)
				if !cfg.PortFilter.SafePorts[port] {
					log.Printf("BLOCKED %s %s (port %d not allowed)", req.Method, req.URL.String(), port)
					if cfg.BlockedLogger != nil {
						cfg.BlockedLogger.Log(clientIP(ctx), req.Method, req.URL.String())
					}
					return req, goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						http.StatusForbidden,
						rejectMsg,
					)
				}
			}

			// Domain filter for non-CONNECT requests (plain HTTP)
			if !cfg.DomainFilter.IsAllowed(hostname) {
				log.Printf("BLOCKED %s %s", req.Method, req.URL.String())
				if cfg.BlockedLogger != nil {
					cfg.BlockedLogger.Log(clientIP(ctx), req.Method, req.URL.String())
				}
				return req, goproxy.NewResponse(req,
					goproxy.ContentTypeText,
					http.StatusForbidden,
					rejectMsg,
				)
			}

			// Intercept OAuth2 token exchange requests.
			if cfg.TokenVendor != nil {
				if resp := cfg.TokenVendor.HandleTokenExchange(req); resp != nil {
					return req, resp
				}
			}

			// Inject credentials for API requests
			if cfg.CredStore != nil {
				switch cfg.CredStore.InjectCredentials(req) {
				case credentials.InjectOK:
					// Buffer the body so a Refresher-backed route can be retried
					// once after an upstream 401; abort if buffering fails.
					if resp := prepareRefreshRetry(req, ctx, cfg.CredStore); resp != nil {
						return req, resp
					}
					// Mark the request as credential-injected so the OnResponse
					// handler logs upstream errors for it. prepareRefreshRetry may
					// have already stashed retry state on ctx.UserData; only set
					// the flag when it didn't, so a buffer-failure abort (UserData
					// still nil) isn't mislogged as an upstream error.
					if ctx.UserData == nil {
						ctx.UserData = credInjectedFlag{}
					}
				case credentials.InjectAuthRequired:
					return req, goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						http.StatusUnauthorized,
						"Authentication required",
					)
				case credentials.InjectFailed:
					return req, goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						http.StatusBadGateway,
						"Proxy credential injection failed",
					)
				}
			}

			// Suppress proxy identity headers
			req.Header.Del("Via")
			req.Header.Del("X-Forwarded-For")

			return req, nil
		},
	)

	// Retry once with a forced-fresh credential if upstream itself rejects
	// the request as unauthorized. This recovers from a credential that
	// InjectCredentials considered locally valid but that the real server
	// disagreed with (e.g. a cached OAuth token whose local expiry check
	// disagreed with Google's after a host suspend/resume cycle).
	//
	// Registered before the upstream-error logger below so a successful
	// recovery replaces the 401 before it would be logged as an upstream error.
	proxy.OnResponse(goproxy.StatusCodeIs(http.StatusUnauthorized)).DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			return retryWithForcedRefresh(resp, ctx, cfg.CredStore)
		},
	)

	// Log upstream error responses for credential-injected requests.
	// This distinguishes proxy-generated errors from upstream errors.
	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp != nil && ctx.UserData != nil && resp.StatusCode >= 400 {
				var host, method, path string
				if ctx.Req != nil {
					method = ctx.Req.Method
					if ctx.Req.URL != nil {
						host = ctx.Req.URL.Host
						path = ctx.Req.URL.Path
					}
				}
				log.Printf("UPSTREAM_ERROR host=%s status=%d method=%s path=%s", host, resp.StatusCode, method, path)
			}
			return resp
		},
	)

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// refreshRetryState is stashed on ctx.UserData by prepareRefreshRetry when a
// request was handled by a credentials.Refresher, so the response handler
// can retry once with a forced-fresh credential after an upstream 401.
type refreshRetryState struct {
	injector credentials.Refresher
	getBody  func() (io.ReadCloser, error)
	retried  bool
}

// maxRetryBufferBytes caps how much of a request body the proxy buffers in
// memory to enable the upstream-401 retry. Requests up to this size get the
// forced-refresh retry safety net; larger ones (e.g. big multimodal Vertex
// inference payloads) are still forwarded intact but stream through without
// buffering, so they can't be retried. This bounds the memory a hostile agent
// can force the proxy to allocate by POSTing huge bodies to a Refresher-backed
// (*.googleapis.com) route.
const maxRetryBufferBytes = 10 << 20 // 10 MiB

// prepareRefreshRetry buffers req's body (if any) and stashes retry state on
// ctx.UserData when the matched injector supports ForceRefresh. Buffering
// the body is required because the original io.ReadCloser is drained by the
// first round trip and can't be replayed as-is; it's skipped for injectors
// that can't force-refresh, since those requests will never be retried.
//
// It returns a non-nil response only when buffering fails: at that point the
// body has already been partially drained and can't be forwarded intact, so
// the caller must abort with that response rather than send a truncated
// request upstream. It returns nil in all other cases (proceed normally).
func prepareRefreshRetry(req *http.Request, ctx *goproxy.ProxyCtx, store *credentials.Store) *http.Response {
	injector, ok := store.MatchInjector(req).(credentials.Refresher)
	if !ok {
		return nil
	}

	if req.Body == nil || req.Body == http.NoBody {
		ctx.UserData = &refreshRetryState{
			injector: injector,
			getBody:  func() (io.ReadCloser, error) { return http.NoBody, nil },
		}
		return nil
	}

	// Read up to the cap plus one byte so we can tell whether the body fit.
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxRetryBufferBytes+1))
	if err != nil {
		// The body is already partially consumed; forwarding it now would
		// send a truncated request upstream. Abort with a 502 instead.
		req.Body.Close()
		log.Printf("ERROR buffering request body for retry: %v", err)
		return goproxy.NewResponse(req,
			goproxy.ContentTypeText,
			http.StatusBadGateway,
			"Proxy failed to buffer request body",
		)
	}

	if len(bodyBytes) > maxRetryBufferBytes {
		// Too large to hold in memory for a retry. Forward the request intact
		// by stitching the already-read prefix back in front of the unread
		// remainder and skip retry setup: an oversized body loses the 401
		// retry safety net but is never truncated nor fully buffered. The
		// struct fields both capture the original req.Body (evaluated before
		// the assignment), so the remainder still streams and Close still
		// closes the underlying body.
		log.Printf("GCLOUD_TOKEN_REFRESH_RETRY host=%s body exceeds %d-byte cap; forwarding without retry", req.URL.Host, maxRetryBufferBytes)
		req.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), req.Body),
			Closer: req.Body,
		}
		return nil
	}

	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	getBody := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	req.GetBody = getBody
	ctx.UserData = &refreshRetryState{injector: injector, getBody: getBody}
	return nil
}

// retryWithForcedRefresh retries a 401 response exactly once with a
// forced-fresh credential, if the original request was prepared for retry
// by prepareRefreshRetry. Returns the original response unchanged otherwise
// (including when the retry itself fails), so callers always get a response.
func retryWithForcedRefresh(resp *http.Response, ctx *goproxy.ProxyCtx, store *credentials.Store) *http.Response {
	state, ok := ctx.UserData.(*refreshRetryState)
	if !ok || state.retried || ctx.Req == nil {
		return resp
	}
	state.retried = true // at most one retry, even if this attempt also fails

	if err := state.injector.ForceRefresh(); err != nil {
		log.Printf("GCLOUD_TOKEN_REFRESH_RETRY force refresh failed: %v", err)
		return resp
	}

	body, err := state.getBody()
	if err != nil {
		log.Printf("GCLOUD_TOKEN_REFRESH_RETRY rebuilding request body failed: %v", err)
		return resp
	}
	ctx.Req.Body = body

	if store.InjectCredentials(ctx.Req) != credentials.InjectOK {
		return resp
	}

	log.Printf("GCLOUD_TOKEN_REFRESH_RETRY host=%s (upstream 401, retrying with forced-fresh token)", ctx.Req.URL.Host)
	newResp, err := ctx.RoundTrip(ctx.Req)
	if err != nil {
		log.Printf("GCLOUD_TOKEN_REFRESH_RETRY retry round-trip failed: %v", err)
		return resp
	}
	// We're discarding the original 401 in favor of newResp — close its body
	// so the underlying connection can be reused instead of leaking.
	if resp.Body != nil {
		resp.Body.Close()
	}
	return newResp
}

func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// extractPort returns the port from a host:port string, or defaultPort if none.
func extractPort(host string, defaultPort int) int {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		if p, err := strconv.Atoi(host[idx+1:]); err == nil {
			return p
		}
	}
	return defaultPort
}

// clientIP extracts the client IP string from a goproxy context (for logging).
func clientIP(ctx *goproxy.ProxyCtx) string {
	if ctx != nil && ctx.Req != nil {
		ip := ctx.Req.RemoteAddr
		// Strip port from RemoteAddr (ip:port)
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			return ip[:idx]
		}
		return ip
	}
	return "-"
}

// parseClientIP extracts and parses the client IP from a goproxy context.
func parseClientIP(ctx *goproxy.ProxyCtx) net.IP {
	if ctx == nil || ctx.Req == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(ctx.Req.RemoteAddr)
	if err != nil {
		return net.ParseIP(ctx.Req.RemoteAddr)
	}
	return net.ParseIP(host)
}

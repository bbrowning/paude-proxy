package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/bbrowning/paude-proxy/internal/credentials"
	"github.com/bbrowning/paude-proxy/internal/filter"
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

// ClientFilter validates client source IPs against an allowlist of IPs and CIDRs.
// A nil or empty ClientFilter allows all clients.
type ClientFilter struct {
	ips  []net.IP
	nets []*net.IPNet
}

// NewClientFilter parses a comma-separated list of IPs and CIDRs.
// Returns nil if the input is empty (allow all).
func NewClientFilter(s string) (*ClientFilter, error) {
	if s == "" {
		return nil, nil
	}
	cf := &ClientFilter{}
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
		} else {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", part)
			}
			cf.ips = append(cf.ips, ip)
		}
	}
	return cf, nil
}

// IsAllowed returns true if the given IP is in the allowlist.
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
	return false
}

// String returns a human-readable representation of the filter.
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
	return strings.Join(parts, ", ")
}

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
	proxy := goproxy.NewProxyHttpServer()
	// Override goproxy's default transport which uses InsecureSkipVerify: true.
	// We MUST verify upstream server TLS certificates to prevent credential theft via MITM.
	proxyTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
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
			// Source IP filtering
			if cfg.ClientFilter != nil {
				srcIP := parseClientIP(ctx)
				if srcIP == nil || !cfg.ClientFilter.IsAllowed(srcIP) {
					log.Printf("CLIENT_REJECTED CONNECT %s from %s (not in allowed clients)", host, clientIP(ctx))
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
				return rejectConnect, host
			}

			if !cfg.DomainFilter.IsAllowed(hostname) {
				log.Printf("BLOCKED CONNECT %s", host)
				if cfg.BlockedLogger != nil {
					cfg.BlockedLogger.Log(clientIP(ctx), "CONNECT", host)
				}
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
			// Source IP filtering for plain HTTP proxy requests.
			// MITM'd HTTPS requests already passed filtering in HandleConnectFunc.
			if cfg.ClientFilter != nil && req.URL.Scheme == "http" {
				srcIP := parseClientIP(ctx)
				if srcIP == nil || !cfg.ClientFilter.IsAllowed(srcIP) {
					log.Printf("CLIENT_REJECTED %s %s from %s (not in allowed clients)", req.Method, req.URL.String(), clientIP(ctx))
					return req, goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						http.StatusForbidden,
						"Client IP not allowed by proxy policy",
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
						"Port not allowed by proxy policy",
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
					"Domain not allowed by proxy policy",
				)
			}

			// Intercept OAuth2 token exchange requests.
			if cfg.TokenVendor != nil && credentials.IsTokenExchange(req) {
				if resp := cfg.TokenVendor.HandleTokenExchange(req); resp != nil {
					return req, resp
				}
			}

			// Inject credentials for API requests
			if cfg.CredStore != nil {
				matched, injected := cfg.CredStore.InjectCredentials(req)
				if matched && !injected {
					log.Printf("CREDENTIAL_INJECT_FAILED_502 method=%s host=%s path=%s", req.Method, req.URL.Host, req.URL.Path)
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

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
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

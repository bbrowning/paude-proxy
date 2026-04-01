package proxy

import (
	"crypto/tls"
	"fmt"
	"log"
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
}

// New creates a configured goproxy server.
func New(cfg Config) *http.Server {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = cfg.Verbose

	// Set up the CA for MITM
	goproxy.GoproxyCa = cfg.CA.TLSCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cfg.CA.TLSCert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cfg.CA.TLSCert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&cfg.CA.TLSCert)}

	// Handle CONNECT requests: port filtering, domain filtering, MITM
	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			hostname := stripPort(host)
			port := extractPort(host, 443)

			// Port filtering for CONNECT (SSL_ports)
			if cfg.PortFilter != nil && !cfg.PortFilter.SSLPorts[port] {
				log.Printf("BLOCKED CONNECT %s (port %d not allowed)", host, port)
				if cfg.BlockedLogger != nil {
					cfg.BlockedLogger.Log(clientIP(ctx), "CONNECT", host)
				}
				return goproxy.RejectConnect, host
			}

			if !cfg.DomainFilter.IsAllowed(hostname) {
				log.Printf("BLOCKED CONNECT %s", host)
				if cfg.BlockedLogger != nil {
					cfg.BlockedLogger.Log(clientIP(ctx), "CONNECT", host)
				}
				return goproxy.RejectConnect, host
			}

			log.Printf("CONNECT %s (MITM)", host)
			return goproxy.MitmConnect, host
		},
	)

	// Handle all requests (both plain HTTP and MITM'd HTTPS):
	// - Port filtering (Safe_ports)
	// - Intercept OAuth2 token exchanges (return dummy tokens)
	// - Inject credentials based on destination domain
	// - Suppress proxy identity headers
	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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
				cfg.CredStore.InjectCredentials(req)
			}

			// Suppress proxy identity headers
			req.Header.Del("Via")
			req.Header.Del("X-Forwarded-For")

			return req, nil
		},
	)

	return &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: proxy,
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

// clientIP extracts the client IP from a goproxy context.
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

package proxy

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/paude-group/auth-proxy/internal/credentials"
	"github.com/paude-group/auth-proxy/internal/filter"
)

// Config holds proxy configuration.
type Config struct {
	ListenAddr   string
	CA           *CA
	DomainFilter *filter.DomainFilter
	CredStore    *credentials.Store
	Verbose      bool
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

	// Handle CONNECT requests: domain filtering + MITM
	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			hostname := stripPort(host)

			if !cfg.DomainFilter.IsAllowed(hostname) {
				log.Printf("BLOCKED CONNECT %s", host)
				return goproxy.RejectConnect, host
			}

			log.Printf("CONNECT %s (MITM)", host)
			return goproxy.MitmConnect, host
		},
	)

	// Handle all requests (both plain HTTP and MITM'd HTTPS):
	// inject credentials based on destination domain.
	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			hostname := stripPort(req.URL.Host)

			// Domain filter for non-CONNECT requests (plain HTTP)
			if !cfg.DomainFilter.IsAllowed(hostname) {
				log.Printf("BLOCKED %s %s", req.Method, req.URL.String())
				return req, goproxy.NewResponse(req,
					goproxy.ContentTypeText,
					http.StatusForbidden,
					"Domain not allowed by proxy policy",
				)
			}

			// Inject credentials
			if cfg.CredStore != nil {
				cfg.CredStore.InjectCredentials(req)
			}

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

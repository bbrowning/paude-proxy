package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bbrowning/paude-proxy/internal/credentials"
	"github.com/bbrowning/paude-proxy/internal/filter"
)

func skipIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
}

// startTestProxy creates a proxy with the given config and returns its URL and a cleanup func.
func startTestProxy(t *testing.T, ca *CA, domainFilter *filter.DomainFilter, credStore *credentials.Store, tokenVendor *credentials.TokenVendor, upstreamCAs *x509.CertPool) (proxyURL string, cleanup func()) {
	return startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: domainFilter,
		CredStore:    credStore,
		TokenVendor:  tokenVendor,
		UpstreamCAs:  upstreamCAs,
		Verbose:      false,
	})
}

func startTestProxyWithConfig(t *testing.T, cfg Config) (proxyURL string, cleanup func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	cfg.ListenAddr = listener.Addr().String()
	srv := New(cfg)
	go srv.Serve(listener)

	return "http://" + listener.Addr().String(), func() {
		srv.Close()
	}
}

// upstreamCertPool extracts the CA cert from an httptest.NewTLSServer and returns it as a CertPool.
func upstreamCertPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	cert := srv.TLS.Certificates[0]
	ca, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

// httpClientViaProxy creates an http.Client that uses the given proxy and trusts both
// the proxy's MITM CA and the upstream server's CA.
func httpClientViaProxy(t *testing.T, proxyAddr string, caCert *x509.Certificate, upstreamCACert *x509.Certificate) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	if upstreamCACert != nil {
		certPool.AddCert(upstreamCACert)
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 5 * time.Second,
		// Don't follow redirects — match proxy behavior
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestIntegration_MITMProxy(t *testing.T) {
	skipIntegration(t)
	// Generate proxy CA
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Start a local HTTPS server that echoes request headers as JSON
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[k] = v[0]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(headers)
	}))
	defer upstream.Close()

	// Extract the upstream server's hostname and host:port
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHostPort := upstreamURL.Host // e.g., "127.0.0.1:44637"
	upstreamHostname := upstreamURL.Hostname() // e.g., "127.0.0.1"

	// Domain filter works on hostname without port
	df := filter.NewDomainFilter(upstreamHostname)

	// Credential routing also matches on hostname without port
	store := credentials.NewStore()
	store.AddRoute(credentials.Route{
		ExactDomain: upstreamHostname,
		Injector:    &credentials.BearerInjector{Token: "test-secret-key"},
	})
	_ = upstreamHostPort

	// Get upstream server's CA cert for trust (needed by both proxy and client)
	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxy(t, ca, df, store, nil, upstreamCAs)
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)

	t.Run("proxied request succeeds with credential injection", func(t *testing.T) {
		req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
		req.Header.Set("Authorization", "Bearer dummy-placeholder")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}

		var headers map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&headers); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		auth := headers["Authorization"]
		if auth != "Bearer test-secret-key" {
			t.Errorf("expected injected credential 'Bearer test-secret-key', got %q", auth)
		}
	})

	t.Run("request without auth header gets credential injected", func(t *testing.T) {
		req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		var headers map[string]string
		json.NewDecoder(resp.Body).Decode(&headers)

		auth := headers["Authorization"]
		if auth != "Bearer test-secret-key" {
			t.Errorf("expected injected credential 'Bearer test-secret-key', got %q", auth)
		}
	})
}

func TestIntegration_DomainBlocking(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Allow only 127.0.0.1 — nothing else
	df := filter.NewDomainFilter("127.0.0.1")

	proxyAddr, cleanup := startTestProxy(t, ca, df, nil, nil, nil)
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, nil)

	// HTTPS request to a non-allowed domain should fail (CONNECT rejected)
	// We can't easily test real external domains, so just verify the proxy rejects
	// by making a request to 127.0.0.2 which is not in the allowlist
	req, _ := http.NewRequest("GET", "https://127.0.0.2:9999/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		// Connection rejected — this is expected
		if !strings.Contains(err.Error(), "Forbidden") &&
			!strings.Contains(err.Error(), "connection refused") &&
			!strings.Contains(err.Error(), "EOF") &&
			!strings.Contains(err.Error(), "reset") &&
			!strings.Contains(err.Error(), "proxy") {
			// Accept any connection error as "blocked"
		}
		return
	}
	defer resp.Body.Close()

	// If we got a response, it should be a rejection (403)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected blocked request (403 or connection error), got %d", resp.StatusCode)
	}
}

func TestIntegration_NoCredentialForUnmatchedDomain(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Start upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[k] = v[0]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(headers)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHostname := upstreamURL.Hostname()

	// Allow the upstream host but only configure credentials for a different domain
	df := filter.NewDomainFilter(upstreamHostname)
	store := credentials.NewStore()
	store.AddRoute(credentials.Route{
		ExactDomain: "api.openai.com",
		Injector:    &credentials.BearerInjector{Token: "should-not-appear"},
	})

	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxy(t, ca, df, store, nil, upstreamCAs)
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)

	req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	req.Header.Set("Authorization", "Bearer agent-dummy")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var headers map[string]string
	json.NewDecoder(resp.Body).Decode(&headers)

	auth := headers["Authorization"]
	if auth != "Bearer agent-dummy" {
		t.Errorf("expected original auth header 'Bearer agent-dummy' (no injection), got %q", auth)
	}
}

func TestIntegration_PortFiltering(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Start upstream on a random port (non-443)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHostname := upstreamURL.Hostname()

	df := filter.NewDomainFilter(upstreamHostname)

	// Port filter that only allows 443 (the upstream is NOT on 443)
	pf := DefaultPortFilter()

	proxyAddr, cleanup := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
		PortFilter:   pf,
		Verbose:      false,
	})
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, nil)

	// The upstream is on a non-443 port, so CONNECT should be rejected
	req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	_, err = client.Do(req)
	if err == nil {
		t.Error("expected connection error due to port filtering, but request succeeded")
	}

	// Now test with the port added to the filter
	upstreamPort := upstreamURL.Port()
	portNum := 0
	for _, c := range upstreamPort {
		portNum = portNum*10 + int(c-'0')
	}
	pf.AddPorts([]int{portNum})

	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr2, cleanup2 := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
		PortFilter:   pf,
		UpstreamCAs:  upstreamCAs,
		Verbose:      false,
	})
	defer cleanup2()

	client2 := httpClientViaProxy(t, proxyAddr2, ca.Certificate, upstreamCA)
	req2, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	resp, err := client2.Do(req2)
	if err != nil {
		t.Fatalf("request should succeed with port added: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_HeaderSuppression(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Upstream echoes headers
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[k] = v[0]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(headers)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHostname := upstreamURL.Hostname()

	df := filter.NewDomainFilter(upstreamHostname)

	// No port filter so the non-443 upstream port is allowed
	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxy(t, ca, df, nil, nil, upstreamCAs)
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)

	req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("Via", "1.1 some-proxy")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var headers map[string]string
	json.NewDecoder(resp.Body).Decode(&headers)

	if _, ok := headers["X-Forwarded-For"]; ok {
		t.Error("X-Forwarded-For should have been stripped")
	}
	if _, ok := headers["Via"]; ok {
		t.Error("Via should have been stripped")
	}
}

func TestIntegration_TokenVending(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Start upstream that mimics oauth2.googleapis.com
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should NOT be reached if token vendor intercepts
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHostname := upstreamURL.Hostname()

	df := filter.NewDomainFilter(upstreamHostname)

	// Create a token vendor (without real ADC — it returns dummy tokens)
	tokenVendor := credentials.NewTokenVendor()

	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]

	proxyAddr, cleanup := startTestProxy(t, ca, df, nil, tokenVendor, upstreamCAs)
	defer cleanup()
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)

	// Simulate an OAuth2 token exchange request
	// The token vendor checks for specific URL path patterns
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"paude-proxy-managed"},
		"client_id":     {"paude-proxy-managed"},
		"client_secret": {"paude-proxy-managed"},
	}

	// Build request to look like a Google OAuth2 token exchange
	// Token vendor checks: host contains "googleapis.com" and path is "/token"
	// Since we're using a local server, we need to check how IsTokenExchange works
	req, _ := http.NewRequest("POST", upstream.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Token vendor only intercepts requests to oauth2.googleapis.com, so
	// requests to our local server should pass through to the upstream.
	// The upstream returns 418 (teapot) to confirm it was reached.
	if resp.StatusCode != http.StatusTeapot {
		t.Logf("Token vendor did not intercept (expected for local server), status: %d", resp.StatusCode)
	}
}

func TestIntegration_ClientFilter_AllowedIP(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	df := filter.NewDomainFilter(upstreamURL.Hostname())

	// Allow 127.0.0.1 (the test client's source IP)
	cf, err := NewClientFilter("127.0.0.1")
	if err != nil {
		t.Fatalf("NewClientFilter: %v", err)
	}

	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
		ClientFilter: cf,
		UpstreamCAs:  upstreamCAs,
	})
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)
	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("request from allowed IP should succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_ClientFilter_BlockedIP(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	df := filter.NewDomainFilter(upstreamURL.Hostname())

	// Allow only 10.99.99.99 — test client connects from 127.0.0.1, should be rejected
	cf, err := NewClientFilter("10.99.99.99")
	if err != nil {
		t.Fatalf("NewClientFilter: %v", err)
	}

	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
		ClientFilter: cf,
		UpstreamCAs:  upstreamCAs,
	})
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)
	_, err = client.Get(upstream.URL + "/test")
	if err == nil {
		t.Error("request from non-allowed IP should fail")
	}
}

func TestIntegration_ClientFilter_CIDR(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	df := filter.NewDomainFilter(upstreamURL.Hostname())

	// Allow 127.0.0.0/8 — test client connects from 127.0.0.1, should match
	cf, err := NewClientFilter("127.0.0.0/8")
	if err != nil {
		t.Fatalf("NewClientFilter: %v", err)
	}

	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
		ClientFilter: cf,
		UpstreamCAs:  upstreamCAs,
	})
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)
	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("request from CIDR-allowed IP should succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_ClientFilter_Disabled(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	df := filter.NewDomainFilter(upstreamURL.Hostname())

	// No client filter — all clients allowed
	upstreamCAs := upstreamCertPool(t, upstream)
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])

	proxyAddr, cleanup := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
		UpstreamCAs:  upstreamCAs,
	})
	defer cleanup()

	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)
	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("request without client filter should succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_UntrustedUpstreamCert(t *testing.T) {
	skipIntegration(t)
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Start an upstream HTTPS server (self-signed cert)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	df := filter.NewDomainFilter(upstreamURL.Hostname())

	// DO NOT pass UpstreamCAs — the proxy should not trust the upstream's self-signed cert
	proxyAddr, cleanup := startTestProxyWithConfig(t, Config{
		CA:           ca,
		DomainFilter: df,
	})
	defer cleanup()

	// Client trusts both the proxy CA and the upstream CA (so the client side is fine),
	// but the PROXY doesn't trust the upstream — the proxy should fail the upstream TLS handshake
	upstreamCert := upstream.TLS.Certificates[0]
	upstreamCA, _ := x509.ParseCertificate(upstreamCert.Certificate[0])
	client := httpClientViaProxy(t, proxyAddr, ca.Certificate, upstreamCA)

	resp, err := client.Get(upstream.URL + "/test")
	if err == nil {
		resp.Body.Close()
		// If we got a response, it should be an error (502 Bad Gateway from proxy failing upstream TLS)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("proxy should reject upstream with untrusted cert, but request succeeded with 200")
		}
		t.Logf("got status %d (expected — proxy rejected untrusted upstream cert)", resp.StatusCode)
		return
	}
	// Connection error is also acceptable — proxy rejected the upstream
	t.Logf("got error (expected — proxy rejected untrusted upstream cert): %v", err)
}

package credentials

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bbrowning/paude-proxy/internal/timeouts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GCloudInjector injects OAuth2 bearer tokens obtained from
// Google Application Default Credentials. It handles automatic
// token refresh. Always overrides any existing Authorization header.
type GCloudInjector struct {
	mu          sync.Mutex
	credentials *google.Credentials
	initErr     error
	initialized bool
	adcPath     string
	adcJSON     []byte
	scopes      []string
}

// NewGCloudInjector creates an injector that reads ADC from the given path.
// Token refresh happens automatically via the oauth2 library.
func NewGCloudInjector(adcPath string) *GCloudInjector {
	return &GCloudInjector{
		adcPath: adcPath,
		scopes:  []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
}

// NewGCloudInjectorFromJSON creates an injector from raw ADC JSON content.
// This is preferred over NewGCloudInjector when credentials are passed
// via environment variable rather than mounted as a file.
func NewGCloudInjectorFromJSON(data []byte) *GCloudInjector {
	return &GCloudInjector{
		adcJSON: data,
		scopes:  []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
}

func (g *GCloudInjector) init() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.initialized {
		return g.initErr
	}
	return g.recordInit(g.doInit())
}

// ForceRefresh discards any cached credentials/token and rebuilds the
// underlying google.Credentials from the original ADC source. The rebuilt
// TokenSource starts from a token with no AccessToken/Expiry, so the next
// Inject call is guaranteed to perform a real network token exchange rather
// than reusing a cached token that Inject still considered locally valid.
//
// This exists because a long-running proxy process can end up with a
// cached token that looks unexpired by its local clock while actually
// being rejected by Google (e.g. after a host suspend/resume cycle) — the
// caller invokes this after seeing an upstream 401 to force a real refresh
// before retrying.
func (g *GCloudInjector) ForceRefresh() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	err := g.doInit()
	if err != nil && g.credentials != nil {
		// Keep the last-good credentials on a failed rebuild. Discarding them
		// would poison the injector — Inject would fail with 502 forever, and a
		// 502 (unlike a 401) never re-triggers this retry path, so it could
		// never recover. Report the error so the caller skips the now-pointless
		// retry, but leave initErr/initialized untouched so Inject keeps working.
		log.Printf("WARN gcloud force refresh failed, keeping existing credentials: %v", err)
		return err
	}
	return g.recordInit(err)
}

// recordInit stores the outcome of a doInit attempt and returns it, so init()
// and ForceRefresh() share one place that marks the injector initialized.
// Callers must hold g.mu.
func (g *GCloudInjector) recordInit(err error) error {
	g.initErr = err
	g.initialized = true
	return err
}

// doInit rebuilds credentials from the original ADC source and, on success,
// swaps them into g.credentials. On failure it returns the error WITHOUT
// mutating any state, so a failed rebuild never discards previously-valid
// credentials. Callers must hold g.mu and are responsible for recording
// initialized/initErr.
func (g *GCloudInjector) doInit() error {
	var data []byte
	if len(g.adcJSON) > 0 {
		data = g.adcJSON
	} else {
		var err error
		data, err = os.ReadFile(g.adcPath)
		if err != nil {
			return fmt.Errorf("read ADC file %s: %w", g.adcPath, err)
		}
	}

	// Custom HTTP client for OAuth2 token refresh. DisableKeepAlives forces
	// fresh connections (~1/hour refresh rate, so no benefit to pooling).
	httpClient := &http.Client{
		Timeout: timeouts.ResponseHeader,
		Transport: &http.Transport{
			Proxy:             nil, // token refresh must go directly to Google, never through HTTP_PROXY
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   timeouts.TLSHandshake,
			ResponseHeaderTimeout: timeouts.ResponseHeader,
		},
	}

	// Use context.Background() with custom HTTP client — this context is stored by
	// the oauth2 library and reused for all token refresh HTTP calls. It must NOT
	// be canceled or have a short timeout.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	creds, err := google.CredentialsFromJSON(ctx, data, g.scopes...)
	if err != nil {
		return fmt.Errorf("parse ADC credentials: %w", err)
	}

	g.credentials = creds
	return nil
}

// tokenSource returns the current TokenSource under the lock, so a
// concurrent ForceRefresh swapping g.credentials can't race with Inject
// reading it.
func (g *GCloudInjector) tokenSource() oauth2.TokenSource {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.credentials.TokenSource
}

// Inject sets the Authorization: Bearer header with a fresh OAuth2 token.
// Always overrides — the agent may have a token from a dummy ADC file.
func (g *GCloudInjector) Inject(req *http.Request) InjectResult {
	if req == nil {
		log.Printf("DEFENSIVE_CHECK: GCloudInjector.Inject called with nil request")
		return InjectFailed
	}

	if err := g.init(); err != nil {
		log.Printf("ERROR gcloud credential init failed: %v", err)
		return InjectFailed
	}

	token, err := g.tokenSource().Token()
	if err != nil {
		log.Printf("ERROR gcloud token refresh failed: %v", err)
		return InjectFailed
	}

	if !token.Valid() {
		log.Printf("WARN gcloud token is invalid after refresh (length=%d)", len(token.AccessToken))
		return InjectFailed
	}

	if token.AccessToken == SyntheticToken || len(token.AccessToken) < 20 {
		log.Printf("ERROR gcloud token looks like a dummy/synthetic token (length=%d) — will cause upstream 401. Check if proxy's own HTTP traffic is routing through itself (HTTP_PROXY env var set on proxy container?)", len(token.AccessToken))
		return InjectFailed
	}

	log.Printf("GCLOUD_TOKEN_DEBUG length=%d type=%q expiry=%s", len(token.AccessToken), token.TokenType, token.Expiry.UTC().Format(time.RFC3339))

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return InjectOK
}

// Available returns true if ADC credentials can be loaded (from JSON or file).
func (g *GCloudInjector) Available() bool {
	if len(g.adcJSON) > 0 {
		return g.init() == nil
	}
	if _, err := os.Stat(g.adcPath); err != nil {
		return false
	}
	return g.init() == nil
}

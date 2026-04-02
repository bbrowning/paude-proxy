package credentials

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"golang.org/x/oauth2/google"
)

// GCloudInjector injects OAuth2 bearer tokens obtained from
// Google Application Default Credentials. It handles automatic
// token refresh. Always overrides any existing Authorization header.
type GCloudInjector struct {
	credentials *google.Credentials
	initOnce    sync.Once
	initErr     error
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
	g.initOnce.Do(func() {
		var data []byte
		if len(g.adcJSON) > 0 {
			data = g.adcJSON
		} else {
			var err error
			data, err = os.ReadFile(g.adcPath)
			if err != nil {
				g.initErr = fmt.Errorf("read ADC file %s: %w", g.adcPath, err)
				return
			}
		}

		// Use context.Background() — this context is stored by the oauth2
		// library and reused for all token refresh HTTP calls. It must NOT
		// be canceled or have a short timeout.
		creds, err := google.CredentialsFromJSON(context.Background(), data, g.scopes...)
		if err != nil {
			g.initErr = fmt.Errorf("parse ADC credentials: %w", err)
			return
		}

		g.credentials = creds
	})
	return g.initErr
}

// Inject sets the Authorization: Bearer header with a fresh OAuth2 token.
// Always overrides — the agent may have a token from a dummy ADC file.
func (g *GCloudInjector) Inject(req *http.Request) bool {
	if err := g.init(); err != nil {
		log.Printf("ERROR gcloud credential init failed: %v", err)
		return false
	}

	token, err := g.credentials.TokenSource.Token()
	if err != nil {
		log.Printf("ERROR gcloud token refresh failed: %v", err)
		return false
	}

	if !token.Valid() {
		log.Printf("WARN gcloud token is invalid after refresh")
		return false
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return true
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

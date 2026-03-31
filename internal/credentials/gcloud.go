package credentials

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/oauth2/google"
)

// GCloudInjector injects OAuth2 bearer tokens obtained from
// Google Application Default Credentials. It handles automatic
// token refresh.
type GCloudInjector struct {
	mu          sync.RWMutex
	credentials *google.Credentials
	initOnce    sync.Once
	initErr     error
	adcPath     string
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

func (g *GCloudInjector) init() error {
	g.initOnce.Do(func() {
		data, err := os.ReadFile(g.adcPath)
		if err != nil {
			g.initErr = fmt.Errorf("read ADC file %s: %w", g.adcPath, err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		creds, err := google.CredentialsFromJSON(ctx, data, g.scopes...)
		if err != nil {
			g.initErr = fmt.Errorf("parse ADC credentials: %w", err)
			return
		}

		g.credentials = creds
	})
	return g.initErr
}

// Inject adds an Authorization: Bearer header with a fresh OAuth2 token.
func (g *GCloudInjector) Inject(req *http.Request) {
	if req.Header.Get("Authorization") != "" {
		return
	}

	if err := g.init(); err != nil {
		log.Printf("ERROR gcloud credential init failed: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()

	token, err := g.credentials.TokenSource.Token()
	if err != nil {
		log.Printf("ERROR gcloud token refresh failed: %v", err)
		return
	}

	if !token.Valid() {
		// Force a new token fetch
		ctx2, cancel2 := context.WithTimeout(ctx, 10*time.Second)
		defer cancel2()
		_ = ctx2 // token source handles refresh internally
		log.Printf("WARN gcloud token is invalid after refresh")
		return
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
}

// Available returns true if the ADC file exists and can be loaded.
func (g *GCloudInjector) Available() bool {
	if _, err := os.Stat(g.adcPath); err != nil {
		return false
	}
	return g.init() == nil
}

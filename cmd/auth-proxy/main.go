package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/paude-group/auth-proxy/internal/credentials"
	"github.com/paude-group/auth-proxy/internal/filter"
	"github.com/paude-group/auth-proxy/internal/proxy"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("auth-proxy starting")

	// Configuration from environment
	listenAddr := envOr("AUTH_PROXY_LISTEN", ":3128")
	caDir := envOr("AUTH_PROXY_CA_DIR", "/data/ca")
	allowedDomains := os.Getenv("ALLOWED_DOMAINS")
	verbose := os.Getenv("AUTH_PROXY_VERBOSE") == "1"

	// Generate CA
	log.Println("Generating CA certificate...")
	ca, err := proxy.GenerateCA()
	if err != nil {
		log.Fatalf("Failed to generate CA: %v", err)
	}

	if err := ca.WriteToDir(caDir); err != nil {
		log.Fatalf("Failed to write CA to %s: %v", caDir, err)
	}
	log.Printf("CA certificate written to %s/ca.crt", caDir)

	// Domain filter
	domainFilter := filter.NewDomainFilter(allowedDomains)
	if domainFilter.AllowAll() {
		log.Println("Domain filtering: DISABLED (all domains allowed)")
	} else {
		log.Printf("Domain filtering: ENABLED (%s)", allowedDomains)
	}

	// Credential store and token vendor
	credStore, tokenVendor := buildCredentialStore(domainFilter)

	// Create and start proxy
	srv := proxy.New(proxy.Config{
		ListenAddr:   listenAddr,
		CA:           ca,
		DomainFilter: domainFilter,
		CredStore:    credStore,
		TokenVendor:  tokenVendor,
		Verbose:      verbose,
	})

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-done
	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("Stopped")
}

// credentialDomains maps credential env vars to the domains they'll be injected for.
// Used for startup validation: warn if credentials are configured but domains aren't allowed.
var credentialDomains = map[string][]string{
	"ANTHROPIC_API_KEY":              {".anthropic.com"},
	"OPENAI_API_KEY":                 {".openai.com"},
	"CURSOR_API_KEY":                 {".cursor.com", ".cursorapi.com"},
	"GH_TOKEN":                       {"github.com", "api.github.com", ".githubusercontent.com"},
	"GOOGLE_APPLICATION_CREDENTIALS": {".googleapis.com"},
}

func buildCredentialStore(domainFilter *filter.DomainFilter) (*credentials.Store, *credentials.TokenVendor) {
	store := credentials.NewStore()
	var tokenVendor *credentials.TokenVendor
	hasCredentials := false

	// Anthropic: x-api-key header
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		store.AddRoute(credentials.Route{
			DomainSuffix: ".anthropic.com",
			Injector:     &credentials.APIKeyInjector{HeaderName: "x-api-key", Key: key},
		})
		log.Println("Credential route: *.anthropic.com -> x-api-key")
		hasCredentials = true
	}

	// OpenAI: Authorization: Bearer
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		store.AddRoute(credentials.Route{
			DomainSuffix: ".openai.com",
			Injector:     &credentials.BearerInjector{Token: key},
		})
		log.Println("Credential route: *.openai.com -> Bearer token")
		hasCredentials = true
	}

	// Cursor: Authorization: Bearer
	if key := os.Getenv("CURSOR_API_KEY"); key != "" {
		for _, suffix := range []string{".cursor.com", ".cursorapi.com"} {
			store.AddRoute(credentials.Route{
				DomainSuffix: suffix,
				Injector:     &credentials.BearerInjector{Token: key},
			})
		}
		log.Println("Credential route: *.cursor.com, *.cursorapi.com -> Bearer token")
		hasCredentials = true
	}

	// GitHub: Authorization: token
	if token := os.Getenv("GH_TOKEN"); token != "" {
		for _, domain := range []string{"github.com", "api.github.com"} {
			store.AddRoute(credentials.Route{
				ExactDomain: domain,
				Injector:    &credentials.GitHubTokenInjector{Token: token},
			})
		}
		store.AddRoute(credentials.Route{
			DomainSuffix: ".githubusercontent.com",
			Injector:     &credentials.GitHubTokenInjector{Token: token},
		})
		log.Println("Credential route: github.com, *.githubusercontent.com -> token")
		hasCredentials = true
	}

	// Google Cloud / Vertex AI: OAuth2 Bearer from ADC
	// Two mechanisms work together:
	// 1. Token vending: intercept agent's OAuth2 token exchange (POST
	//    oauth2.googleapis.com/token) and return a DUMMY token. The
	//    agent never sees any real credential.
	// 2. Header injection: override the dummy Authorization header on
	//    API requests to *.googleapis.com with a real Bearer token
	//    obtained from the proxy's own ADC.
	adcPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if adcPath != "" {
		gcloudInjector := credentials.NewGCloudInjector(adcPath)
		if gcloudInjector.Available() {
			store.AddRoute(credentials.Route{
				DomainSuffix: ".googleapis.com",
				Injector:     gcloudInjector,
			})
			tokenVendor = credentials.NewTokenVendor()
			log.Println("Credential route: *.googleapis.com -> gcloud ADC Bearer token")
			log.Println("Token vendor: ENABLED (returns dummy tokens for oauth2.googleapis.com/token)")
			hasCredentials = true
		} else {
			log.Printf("WARN: GOOGLE_APPLICATION_CREDENTIALS=%s but ADC not loadable", adcPath)
		}
	}

	if !hasCredentials {
		log.Println("No credential routes configured")
	}

	// Validate: warn if credentials are configured but their domains aren't allowed
	if !domainFilter.AllowAll() {
		for envVar, domains := range credentialDomains {
			if os.Getenv(envVar) == "" {
				continue
			}
			for _, domain := range domains {
				// Test with a representative hostname
				testHost := domain
				if domain[0] == '.' {
					testHost = "test" + domain
				}
				if !domainFilter.IsAllowed(testHost) {
					log.Printf("WARN: %s is set but domain %s is not in ALLOWED_DOMAINS — credentials will never be injected for this domain", envVar, domain)
				}
			}
		}
	}

	return store, tokenVendor
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

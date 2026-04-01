package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bbrowning/paude-proxy/internal/credentials"
	"github.com/bbrowning/paude-proxy/internal/filter"
	"github.com/bbrowning/paude-proxy/internal/proxy"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("paude-proxy starting")

	// Configuration from environment
	listenAddr := envOr("PAUDE_PROXY_LISTEN", ":3128")
	caDir := envOr("PAUDE_PROXY_CA_DIR", "/data/ca")
	allowedDomains := os.Getenv("ALLOWED_DOMAINS")
	verbose := os.Getenv("PAUDE_PROXY_VERBOSE") == "1"
	blockedLogPath := envOr("BLOCKED_LOG_PATH", "/tmp/squid-blocked.log")
	otelPortsStr := os.Getenv("ALLOWED_OTEL_PORTS")

	// Client IP filtering (optional, for defense-in-depth)
	allowedClients := os.Getenv("PAUDE_PROXY_ALLOWED_CLIENTS")
	clientFilter, err := proxy.NewClientFilter(allowedClients)
	if err != nil {
		log.Fatalf("Invalid PAUDE_PROXY_ALLOWED_CLIENTS: %v", err)
	}
	if clientFilter != nil {
		log.Printf("Client IP filtering: ENABLED (%s)", clientFilter)
	} else {
		log.Println("Client IP filtering: DISABLED (all clients allowed)")
	}

	// Load existing CA or generate a new one
	ca, err := proxy.LoadCAFromDir(caDir)
	if err != nil {
		log.Fatalf("Failed to load existing CA from %s: %v", caDir, err)
	}
	if ca != nil {
		log.Printf("Reusing existing CA from %s/ca.crt", caDir)
	} else {
		log.Println("Generating new CA certificate...")
		ca, err = proxy.GenerateCA()
		if err != nil {
			log.Fatalf("Failed to generate CA: %v", err)
		}
		if err := ca.WriteToDir(caDir); err != nil {
			log.Fatalf("Failed to write CA to %s: %v", caDir, err)
		}
		log.Printf("CA certificate written to %s/ca.crt", caDir)
	}

	// Domain filter
	domainFilter := filter.NewDomainFilter(allowedDomains)
	if domainFilter.AllowAll() {
		log.Println("Domain filtering: DISABLED (all domains allowed)")
	} else {
		log.Printf("Domain filtering: ENABLED (%s)", allowedDomains)
	}

	// Port filter
	portFilter := proxy.DefaultPortFilter()
	if otelPortsStr != "" {
		otelPorts, err := proxy.ParseOTELPorts(otelPortsStr)
		if err != nil {
			log.Fatalf("Invalid ALLOWED_OTEL_PORTS: %v", err)
		}
		portFilter.AddPorts(otelPorts)
		log.Printf("Port filtering: additional OTEL ports %v", otelPorts)
	}

	// Blocked domain logger
	blockedLogger, err := proxy.NewBlockedLogger(blockedLogPath)
	if err != nil {
		log.Fatalf("Failed to open blocked log %s: %v", blockedLogPath, err)
	}
	defer blockedLogger.Close()
	log.Printf("Blocked request log: %s", blockedLogPath)

	// Credential store and token vendor
	credStore, tokenVendor := buildCredentialStore(domainFilter)

	// Create and start proxy
	srv := proxy.New(proxy.Config{
		ListenAddr:    listenAddr,
		CA:            ca,
		DomainFilter:  domainFilter,
		CredStore:     credStore,
		TokenVendor:   tokenVendor,
		PortFilter:    portFilter,
		BlockedLogger: blockedLogger,
		Verbose:       verbose,
		ClientFilter:  clientFilter,
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

func buildCredentialStore(domainFilter *filter.DomainFilter) (*credentials.Store, *credentials.TokenVendor) {
	var cfg *credentials.CredentialConfig
	var err error

	configPath := os.Getenv("PAUDE_PROXY_CREDENTIALS_CONFIG")
	if configPath != "" {
		log.Printf("Loading credential config from %s", configPath)
		cfg, err = credentials.LoadConfig(configPath)
	} else {
		log.Println("Using default credential config")
		cfg, err = credentials.LoadDefaultConfig()
	}
	if err != nil {
		log.Fatalf("Failed to load credential config: %v", err)
	}

	store, tokenVendor, domainMap := credentials.BuildFromConfig(cfg)

	// Validate: warn if credentials are configured but their domains aren't allowed
	if !domainFilter.AllowAll() {
		for envVar, domains := range domainMap {
			for _, domain := range domains {
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

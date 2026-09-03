package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/bbrowning/paude-proxy/internal/filter"
)

func TestLoadDestinationFiltersRejectsPortInAllowedDomains(t *testing.T) {
	_, _, err := loadDestinationFilters("api.example.com:8443", "")
	if err == nil {
		t.Fatal("loadDestinationFilters succeeded, want error")
	}
	if message := err.Error(); !strings.Contains(message, "invalid ALLOWED_DOMAINS") || !strings.Contains(message, "ALLOWED_ENDPOINTS") {
		t.Fatalf("startup error is not actionable: %q", message)
	}
}

func TestLoadDestinationFiltersAllowsEndpointServiceNames(t *testing.T) {
	domains, endpoints, err := loadDestinationFilters("api_service", "api_service:8000")
	if err != nil {
		t.Fatalf("loadDestinationFilters: %v", err)
	}
	if !domains.IsAllowed("api_service:8000") || !endpoints.IsAllowed("api_service", 8000) {
		t.Error("service-name destination was not canonicalized consistently")
	}
}

func TestWarnDisallowedEndpoints(t *testing.T) {
	var output bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	endpoints, err := filter.NewEndpointFilter("allowed.example:8000,blocked.example:8443,also-blocked.example:9000")
	if err != nil {
		t.Fatal(err)
	}
	warnDisallowedEndpoints(filter.NewDomainFilter("allowed.example"), endpoints)

	logs := output.String()
	if strings.Count(logs, "WARN:") != 2 {
		t.Fatalf("warning count = %d, want 2; logs: %s", strings.Count(logs, "WARN:"), logs)
	}
	if strings.Contains(logs, "allowed.example:8000") || !strings.Contains(logs, "blocked.example:8443") || !strings.Contains(logs, "also-blocked.example:9000") {
		t.Errorf("warnings did not identify exactly the unusable authorities: %s", logs)
	}

	output.Reset()
	warnDisallowedEndpoints(filter.NewDomainFilter(""), endpoints)
	if output.Len() != 0 {
		t.Errorf("allow-all ALLOWED_DOMAINS produced warnings: %s", output.String())
	}
}

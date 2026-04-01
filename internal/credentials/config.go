package credentials

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

//go:embed credentials.json
var DefaultConfigJSON []byte

// CredentialConfig is the top-level JSON config for credential routing.
type CredentialConfig struct {
	Credentials []CredentialEntry `json:"credentials"`
}

// CredentialEntry maps an environment variable to an injector type and
// the domains where that credential should be injected.
type CredentialEntry struct {
	// EnvVar is the environment variable name to read the credential from.
	EnvVar string `json:"env_var"`

	// InjectorType is one of: "bearer", "api_key", "github_token", "gcloud".
	InjectorType string `json:"injector"`

	// Params holds injector-specific parameters (e.g., "header_name" for api_key).
	Params map[string]string `json:"params,omitempty"`

	// Domains lists domain patterns. Prefix with "." for suffix/wildcard
	// match (e.g., ".openai.com" matches "api.openai.com"). Without prefix,
	// matches exactly (e.g., "github.com").
	Domains []string `json:"domains"`
}

var validInjectorTypes = map[string]bool{
	"bearer":       true,
	"api_key":      true,
	"github_token": true,
	"gcloud":       true,
}

// ParseConfig parses and validates a credential config from JSON bytes.
func ParseConfig(data []byte) (*CredentialConfig, error) {
	var cfg CredentialConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse credential config: %w", err)
	}

	for i, entry := range cfg.Credentials {
		if entry.EnvVar == "" {
			return nil, fmt.Errorf("credential entry %d: env_var is required", i)
		}
		if !validInjectorTypes[entry.InjectorType] {
			return nil, fmt.Errorf("credential entry %d (%s): invalid injector type %q (valid: bearer, api_key, github_token, gcloud)", i, entry.EnvVar, entry.InjectorType)
		}
		if len(entry.Domains) == 0 {
			return nil, fmt.Errorf("credential entry %d (%s): at least one domain is required", i, entry.EnvVar)
		}
		for j, domain := range entry.Domains {
			if domain == "" {
				return nil, fmt.Errorf("credential entry %d (%s): domain %d is empty", i, entry.EnvVar, j)
			}
		}
		if entry.InjectorType == "api_key" {
			if entry.Params == nil || entry.Params["header_name"] == "" {
				return nil, fmt.Errorf("credential entry %d (%s): api_key injector requires params.header_name", i, entry.EnvVar)
			}
		}
	}

	return &cfg, nil
}

// LoadConfig reads and parses a credential config from a file path.
func LoadConfig(path string) (*CredentialConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential config %s: %w", path, err)
	}
	return ParseConfig(data)
}

// LoadDefaultConfig parses the embedded default credential config.
func LoadDefaultConfig() (*CredentialConfig, error) {
	return ParseConfig(DefaultConfigJSON)
}

// BuildFromConfig creates a credential Store and optional TokenVendor from
// a parsed config. It reads credential values from environment variables.
// Returns the store, token vendor (nil if no gcloud entry), and a map of
// env var names to their domain lists (for domain filter validation).
func BuildFromConfig(cfg *CredentialConfig) (*Store, *TokenVendor, map[string][]string) {
	store := NewStore()
	var tokenVendor *TokenVendor
	hasCredentials := false
	domainMap := make(map[string][]string)

	for _, entry := range cfg.Credentials {
		value := os.Getenv(entry.EnvVar)
		if value == "" {
			continue
		}

		domainMap[entry.EnvVar] = entry.Domains

		var injector Injector
		switch entry.InjectorType {
		case "bearer":
			injector = &BearerInjector{Token: value}
		case "api_key":
			injector = &APIKeyInjector{
				HeaderName: entry.Params["header_name"],
				Key:        value,
			}
		case "github_token":
			injector = &GitHubTokenInjector{Token: value}
		case "gcloud":
			gcloudInjector := NewGCloudInjector(value)
			if !gcloudInjector.Available() {
				log.Printf("WARN: %s=%s but ADC not loadable", entry.EnvVar, value)
				continue
			}
			injector = gcloudInjector
			tokenVendor = NewTokenVendor()
			log.Println("Token vendor: ENABLED (returns dummy tokens for oauth2.googleapis.com/token)")
		}

		for _, domain := range entry.Domains {
			route := Route{Injector: injector}
			if strings.HasPrefix(domain, ".") {
				route.DomainSuffix = domain
			} else {
				route.ExactDomain = domain
			}
			store.AddRoute(route)
		}

		// Log the credential route
		domainDesc := formatDomains(entry.Domains)
		log.Printf("Credential route: %s -> %s", domainDesc, injectorDescription(entry))
		hasCredentials = true
	}

	if !hasCredentials {
		log.Println("No credential routes configured")
	}

	return store, tokenVendor, domainMap
}

func formatDomains(domains []string) string {
	parts := make([]string, len(domains))
	for i, d := range domains {
		if strings.HasPrefix(d, ".") {
			parts[i] = "*" + d
		} else {
			parts[i] = d
		}
	}
	return strings.Join(parts, ", ")
}

func injectorDescription(entry CredentialEntry) string {
	switch entry.InjectorType {
	case "bearer":
		return "Bearer token"
	case "api_key":
		return entry.Params["header_name"]
	case "github_token":
		return "token"
	case "gcloud":
		return "gcloud ADC Bearer token"
	default:
		return entry.InjectorType
	}
}

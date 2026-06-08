package credentials

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// AnthropicOAuthInjector injects an Authorization: Bearer header using the
// Claude subscription OAuth access token from the credentials file. It no
// longer self-refreshes — token rotation is handled externally via
// UpdateFromRefresh (called by the refresh-intercept layer). Always overrides
// the Authorization header on matching requests.
type AnthropicOAuthInjector struct {
	credsPath string

	mu        sync.Mutex
	full      credentialsFile // cached full struct; patched on refresh to preserve scopes etc.
	access    string
	refresh   string
	expiresAt time.Time
	loaded    bool
}

// credentialsFile mirrors ~/.claude/.credentials.json.
type credentialsFile struct {
	ClaudeAiOauth struct {
		AccessToken      string   `json:"accessToken"`
		RefreshToken     string   `json:"refreshToken"`
		ExpiresAt        int64    `json:"expiresAt"` // unix millis
		Scopes           []string `json:"scopes,omitempty"`
		SubscriptionType string   `json:"subscriptionType,omitempty"`
	} `json:"claudeAiOauth"`
}

// NewAnthropicOAuthInjector reads credentials from credsPath on first use.
func NewAnthropicOAuthInjector(credsPath string) *AnthropicOAuthInjector {
	return &AnthropicOAuthInjector{credsPath: credsPath}
}

func (a *AnthropicOAuthInjector) load() error {
	if a.loaded {
		return nil
	}
	data, err := os.ReadFile(a.credsPath)
	if err != nil {
		return fmt.Errorf("read anthropic creds %s: %w", a.credsPath, err)
	}
	var cf credentialsFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("parse anthropic creds: %w", err)
	}
	a.full = cf
	a.access = cf.ClaudeAiOauth.AccessToken
	a.refresh = cf.ClaudeAiOauth.RefreshToken
	a.expiresAt = time.UnixMilli(cf.ClaudeAiOauth.ExpiresAt)
	a.loaded = true
	return nil
}

func (a *AnthropicOAuthInjector) persistLocked() error {
	// Patch only the token fields; leave scopes, subscriptionType, and any
	// other fields in a.full intact to avoid erasing them on write.
	a.full.ClaudeAiOauth.AccessToken = a.access
	a.full.ClaudeAiOauth.RefreshToken = a.refresh
	a.full.ClaudeAiOauth.ExpiresAt = a.expiresAt.UnixMilli()
	data, err := json.Marshal(&a.full)
	if err != nil {
		return err
	}
	tmp := a.credsPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.credsPath)
}

// Inject sets Authorization: Bearer with the cached access token. Always overrides.
func (a *AnthropicOAuthInjector) Inject(req *http.Request) bool {
	if req == nil {
		log.Printf("DEFENSIVE_CHECK: AnthropicOAuthInjector.Inject called with nil request")
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(); err != nil {
		log.Printf("ERROR anthropic creds load: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+a.access)
	return true
}

// Available returns true if the credentials file can be loaded. As a side
// effect it primes the lazy load (sets loaded=true), so a subsequent Inject()
// call reuses the cached credentials without re-reading the file.
func (a *AnthropicOAuthInjector) Available() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.load() == nil
}

// CurrentRefreshToken returns the real refresh token (for the refresh intercept).
func (a *AnthropicOAuthInjector) CurrentRefreshToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(); err != nil {
		log.Printf("ERROR anthropic creds load: %v", err)
		return ""
	}
	return a.refresh
}

// UpdateFromRefresh records rotated tokens (from an intercepted CC refresh) and
// persists them back to the creds file, preserving non-token fields.
func (a *AnthropicOAuthInjector) UpdateFromRefresh(access, refresh string, expiresIn int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.access = access
	if refresh != "" {
		a.refresh = refresh
	}
	a.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	if err := a.persistLocked(); err != nil {
		log.Printf("ERROR anthropic creds persist: %v", err)
	}
}

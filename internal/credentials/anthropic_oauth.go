package credentials

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bbrowning/paude-proxy/internal/timeouts"
)

const (
	anthropicTokenURL      = "https://console.anthropic.com/v1/oauth/token"
	anthropicRefreshWindow = 5 * time.Minute
)

// AnthropicOAuthConfig contains settings for the Anthropic OAuth injector.
// HTTPClient, Now, and RefreshWindow are injectable for tests.
type AnthropicOAuthConfig struct {
	CredsPath     string
	ClientID      string
	HTTPClient    *http.Client
	Now           func() time.Time
	RefreshWindow time.Duration
}

type anthropicOAuthTokens struct {
	AccessToken      string   `json:"accessToken"`
	RefreshToken     string   `json:"refreshToken"`
	ExpiresAt        int64    `json:"expiresAt"`
	ClientID         string   `json:"clientId,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	SubscriptionType string   `json:"subscriptionType,omitempty"`
}

type anthropicOAuthDocument struct {
	topLevel map[string]json.RawMessage
	oauth    anthropicOAuthTokens
}

// AnthropicOAuthInjector supplies Anthropic OAuth Bearer tokens for Claude
// subscription auth. It handles its own token refresh internally.
type AnthropicOAuthInjector struct {
	config AnthropicOAuthConfig

	mu       sync.Mutex
	loaded   bool
	loadErr  error
	document anthropicOAuthDocument
}

// NewAnthropicOAuthInjector creates an injector backed by a credentials file.
func NewAnthropicOAuthInjector(credsPath string) *AnthropicOAuthInjector {
	return NewAnthropicOAuthInjectorWithConfig(AnthropicOAuthConfig{
		CredsPath: credsPath,
	})
}

// NewAnthropicOAuthInjectorWithConfig creates an injector with explicit settings.
func NewAnthropicOAuthInjectorWithConfig(config AnthropicOAuthConfig) *AnthropicOAuthInjector {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.RefreshWindow == 0 {
		config.RefreshWindow = anthropicRefreshWindow
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: timeouts.ResponseHeader,
			Transport: &http.Transport{
				Proxy:                 nil,
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout:   timeouts.TLSHandshake,
				ResponseHeaderTimeout: timeouts.ResponseHeader,
				DisableKeepAlives:     true,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &AnthropicOAuthInjector{config: config}
}

// Available reports whether the credentials path is configured.
func (a *AnthropicOAuthInjector) Available() bool {
	return a.config.CredsPath != ""
}

// Inject sets the Authorization Bearer header. Returns InjectAuthRequired
// when no tokens are loaded yet.
func (a *AnthropicOAuthInjector) Inject(req *http.Request) InjectResult {
	if !validateRequest(req, "AnthropicOAuthInjector") {
		return InjectFailed
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.ensureLoadedLocked(); err != nil {
		log.Printf("ERROR anthropic oauth credential initialization failed")
		return InjectFailed
	}
	if a.document.oauth.RefreshToken == "" {
		log.Printf("WARN anthropic oauth credential not available: no tokens loaded")
		return InjectAuthRequired
	}
	if a.needsRefreshLocked() {
		if err := a.refreshLocked(); err != nil {
			log.Printf("ERROR anthropic oauth credential refresh failed")
			return InjectFailed
		}
	}

	if a.document.oauth.AccessToken == "" {
		log.Printf("WARN anthropic oauth credential incomplete: no access token")
		return InjectFailed
	}
	req.Header.Set("Authorization", "Bearer "+a.document.oauth.AccessToken)
	return InjectOK
}

// SetClientID records the OAuth client_id for use in token refresh. Called by
// the token vendor when it captures the client_id from the agent's request.
func (a *AnthropicOAuthInjector) SetClientID(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.ClientID == "" && id != "" {
		a.config.ClientID = id
	}
}

func (a *AnthropicOAuthInjector) ensureLoadedLocked() error {
	if a.loaded {
		return a.loadErr
	}

	if a.config.CredsPath == "" {
		a.loaded = true
		a.loadErr = errors.New("credentials path is not configured")
		return a.loadErr
	}

	if _, err := os.Stat(a.config.CredsPath); os.IsNotExist(err) {
		// Don't cache — file may appear later (e.g. async volume mount).
		return nil
	} else if err != nil {
		a.loaded = true
		a.loadErr = errors.New("credentials file is unavailable")
		return a.loadErr
	}

	a.loaded = true
	return a.loadFromFileLocked(a.config.CredsPath)
}

func (a *AnthropicOAuthInjector) loadFromFileLocked(path string) error {
	data, err := readPrivateSecretFile(path)
	if err != nil {
		a.loadErr = errors.New("credentials file is unavailable or has insecure permissions")
		return a.loadErr
	}

	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		a.loadErr = errors.New("credentials file is malformed")
		return a.loadErr
	}

	raw, ok := topLevel["claudeAiOauth"]
	if !ok {
		a.loadErr = errors.New("credentials file missing claudeAiOauth")
		return a.loadErr
	}

	var oauth anthropicOAuthTokens
	if err := json.Unmarshal(raw, &oauth); err != nil {
		a.loadErr = errors.New("credentials file claudeAiOauth is malformed")
		return a.loadErr
	}

	a.document = anthropicOAuthDocument{topLevel: topLevel, oauth: oauth}
	if oauth.ClientID != "" && a.config.ClientID == "" {
		a.config.ClientID = oauth.ClientID
	}
	return nil
}

func (a *AnthropicOAuthInjector) needsRefreshLocked() bool {
	if a.document.oauth.ExpiresAt == 0 {
		return true
	}
	return !a.config.Now().Add(a.config.RefreshWindow).Before(time.UnixMilli(a.document.oauth.ExpiresAt))
}

func (a *AnthropicOAuthInjector) refreshLocked() error {
	clientID := a.config.ClientID
	if clientID == "" {
		return errors.New("no client_id available for token refresh")
	}

	body, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": a.document.oauth.RefreshToken,
		"client_id":     clientID,
	})
	if err != nil {
		return errors.New("construct refresh request body")
	}

	req, err := http.NewRequest(http.MethodPost, anthropicTokenURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("construct refresh request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.config.HTTPClient.Do(req)
	if err != nil {
		return errors.New("refresh request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.New("refresh endpoint rejected request")
	}

	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&refreshed); err != nil || refreshed.AccessToken == "" {
		return errors.New("refresh response is malformed")
	}

	updated := a.document
	updated.topLevel = cloneRawFields(a.document.topLevel)
	updated.oauth.AccessToken = refreshed.AccessToken
	if refreshed.RefreshToken != "" {
		updated.oauth.RefreshToken = refreshed.RefreshToken
	}

	now := a.config.Now()
	if refreshed.ExpiresIn > 0 {
		updated.oauth.ExpiresAt = now.Add(time.Duration(refreshed.ExpiresIn) * time.Second).UnixMilli()
	}

	rawOAuth, err := json.Marshal(updated.oauth)
	if err != nil {
		return errors.New("marshal refreshed credentials")
	}
	updated.topLevel["claudeAiOauth"] = rawOAuth

	data, err := json.Marshal(updated.topLevel)
	if err != nil {
		return errors.New("marshal refreshed credentials file")
	}
	if err := atomicWritePrivateSecret(a.config.CredsPath, data); err != nil {
		return errors.New("persist refreshed credentials")
	}

	a.document = updated
	return nil
}

// AcceptLoginTokens processes a successful login exchange response,
// persists the real tokens, and updates in-memory state.
func (a *AnthropicOAuthInjector) AcceptLoginTokens(responseBody []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(responseBody, &raw); err != nil || raw.AccessToken == "" || raw.RefreshToken == "" {
		return errors.New("login response is malformed or incomplete")
	}

	now := a.config.Now()
	oauth := anthropicOAuthTokens{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
	}
	if raw.ExpiresIn > 0 {
		oauth.ExpiresAt = now.Add(time.Duration(raw.ExpiresIn) * time.Second).UnixMilli()
	}

	topLevel := make(map[string]json.RawMessage)
	rawOAuth, err := json.Marshal(oauth)
	if err != nil {
		return errors.New("marshal login tokens")
	}
	topLevel["claudeAiOauth"] = rawOAuth

	if a.config.CredsPath == "" {
		return errors.New("credentials path not configured")
	}
	data, err := json.Marshal(topLevel)
	if err != nil {
		return errors.New("marshal login state")
	}
	if err := atomicWritePrivateSecret(a.config.CredsPath, data); err != nil {
		return errors.New("persist login state")
	}

	a.document = anthropicOAuthDocument{topLevel: topLevel, oauth: oauth}
	a.loaded = true
	a.loadErr = nil
	return nil
}

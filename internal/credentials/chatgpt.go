package credentials

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bbrowning/paude-proxy/internal/timeouts"
)

const (
	chatGPTTokenURL        = "https://auth.openai.com/oauth/token"
	chatGPTClientID        = "app_EMoamEEZ73f0CkXaXp7hrann"
	chatGPTRefreshWindow   = 5 * time.Minute
	chatGPTAuthNamespace   = "https://api.openai.com/auth"
	chatGPTAccountHeader   = "ChatGPT-Account-ID"
	chatGPTDefaultAuthMode = "chatgpt"
)

// ChatGPTOAuthConfig contains the proxy-side locations and HTTP settings for
// ChatGPT OAuth. HTTPClient, Now, and RefreshWindow are injectable for tests;
// production callers should leave them empty.
type ChatGPTOAuthConfig struct {
	AuthPath      string
	StatePath     string
	ClientID      string
	HTTPClient    *http.Client
	Now           func() time.Time
	RefreshWindow time.Duration
}

type chatGPTTokens struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id,omitempty"`
}

type chatGPTDocument struct {
	fields map[string]json.RawMessage
	tokens chatGPTTokens
}

// ChatGPTInjector supplies the current ChatGPT OAuth access token and account
// identifier. It never trusts the Authorization or account headers supplied by
// the agent.
type ChatGPTInjector struct {
	config ChatGPTOAuthConfig

	mu        sync.Mutex
	loaded    bool
	loadErr   error
	document  chatGPTDocument
	expiresAt time.Time
}

// NewChatGPTInjector creates an injector backed by a Codex auth file.
func NewChatGPTInjector(authPath, statePath string) *ChatGPTInjector {
	return NewChatGPTInjectorWithConfig(ChatGPTOAuthConfig{
		AuthPath:  authPath,
		StatePath: statePath,
	})
}

// NewChatGPTInjectorWithConfig creates an injector with explicit settings.
func NewChatGPTInjectorWithConfig(config ChatGPTOAuthConfig) *ChatGPTInjector {
	if config.ClientID == "" {
		config.ClientID = chatGPTClientID
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.RefreshWindow == 0 {
		config.RefreshWindow = chatGPTRefreshWindow
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: timeouts.ResponseHeader,
			Transport: &http.Transport{
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
	return &ChatGPTInjector{config: config}
}

// Available reports whether the configured auth file can be loaded safely.
func (c *ChatGPTInjector) Available() bool {
	return c.ensureLoaded() == nil
}

// Inject sets the ChatGPT Authorization and account headers. Refresh failures
// return false without modifying either header.
func (c *ChatGPTInjector) Inject(req *http.Request) bool {
	if !validateRequest(req, "ChatGPTInjector") {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureLoadedLocked(); err != nil {
		log.Printf("ERROR chatgpt credential initialization failed")
		return false
	}
	if c.needsRefreshLocked() {
		if err := c.refreshLocked(); err != nil {
			log.Printf("ERROR chatgpt credential refresh failed")
			return false
		}
	}

	accountID := c.accountIDLocked()
	if c.document.tokens.AccessToken == "" || accountID == "" {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+c.document.tokens.AccessToken)
	req.Header.Set(chatGPTAccountHeader, accountID)
	return true
}

func (c *ChatGPTInjector) ensureLoaded() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureLoadedLocked()
}

func (c *ChatGPTInjector) ensureLoadedLocked() error {
	if c.loaded {
		return c.loadErr
	}
	c.loaded = true

	if c.config.AuthPath == "" {
		c.loadErr = errors.New("auth source is not configured")
		return c.loadErr
	}
	if c.config.StatePath != "" && samePath(c.config.AuthPath, c.config.StatePath) {
		c.loadErr = errors.New("auth source and state paths must differ")
		return c.loadErr
	}

	path := c.config.AuthPath
	if c.config.StatePath != "" {
		if _, err := os.Stat(c.config.StatePath); err == nil {
			path = c.config.StatePath
		} else if !os.IsNotExist(err) {
			c.loadErr = errors.New("auth state is unavailable")
			return c.loadErr
		}
	}

	data, err := readPrivateSecretFile(path)
	if err != nil {
		c.loadErr = errors.New("auth file is unavailable or has insecure permissions")
		return c.loadErr
	}
	document, err := parseChatGPTDocument(data)
	if err != nil {
		c.loadErr = errors.New("auth file is malformed or incompatible")
		return c.loadErr
	}
	c.document = document
	c.expiresAt = jwtExpiry(document.tokens.AccessToken)
	return nil
}

func parseChatGPTDocument(data []byte) (chatGPTDocument, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return chatGPTDocument{}, err
	}
	if fields == nil {
		return chatGPTDocument{}, errors.New("auth document is not an object")
	}

	if raw, ok := fields["auth_mode"]; ok {
		var mode string
		if err := json.Unmarshal(raw, &mode); err != nil {
			return chatGPTDocument{}, err
		}
		if mode != "" && mode != chatGPTDefaultAuthMode {
			return chatGPTDocument{}, errors.New("auth mode is not chatgpt")
		}
	}
	rawTokens, ok := fields["tokens"]
	if !ok {
		return chatGPTDocument{}, errors.New("tokens are missing")
	}
	var tokens chatGPTTokens
	if err := json.Unmarshal(rawTokens, &tokens); err != nil {
		return chatGPTDocument{}, err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return chatGPTDocument{}, errors.New("oauth tokens are incomplete")
	}

	document := chatGPTDocument{fields: fields, tokens: tokens}
	if document.accountID() == "" {
		return chatGPTDocument{}, errors.New("account id is missing")
	}
	return document, nil
}

func (c *ChatGPTInjector) needsRefreshLocked() bool {
	return c.expiresAt.IsZero() || !c.config.Now().Add(c.config.RefreshWindow).Before(c.expiresAt)
}

func (c *ChatGPTInjector) refreshLocked() error {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.document.tokens.RefreshToken},
		"client_id":     {c.config.ClientID},
	}
	req, err := http.NewRequest(http.MethodPost, chatGPTTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("construct refresh request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.config.HTTPClient.Do(req)
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
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&refreshed); err != nil || refreshed.AccessToken == "" {
		return errors.New("refresh response is malformed")
	}

	updated := c.document
	updated.fields = cloneRawFields(c.document.fields)
	updated.tokens.AccessToken = refreshed.AccessToken
	if refreshed.RefreshToken != "" {
		updated.tokens.RefreshToken = refreshed.RefreshToken
	}
	if refreshed.IDToken != "" {
		updated.tokens.IDToken = refreshed.IDToken
	}
	if updated.accountID() == "" {
		return errors.New("refreshed account id is missing")
	}
	rawTokens, err := json.Marshal(updated.tokens)
	if err != nil {
		return errors.New("marshal refreshed auth state")
	}
	updated.fields["tokens"] = rawTokens
	lastRefresh, _ := json.Marshal(c.config.Now().UTC().Format(time.RFC3339))
	updated.fields["last_refresh"] = lastRefresh

	if c.config.StatePath != "" {
		data, err := json.Marshal(updated.fields)
		if err != nil || atomicWritePrivateSecret(c.config.StatePath, data) != nil {
			return errors.New("persist refreshed auth state")
		}
	}

	c.document = updated
	c.expiresAt = jwtExpiry(updated.tokens.AccessToken)
	if c.expiresAt.IsZero() && refreshed.ExpiresIn > 0 {
		c.expiresAt = c.config.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second)
	}
	return nil
}

func (d chatGPTDocument) accountID() string {
	if d.tokens.AccountID != "" {
		return d.tokens.AccountID
	}
	return accountIDFromIDToken(d.tokens.IDToken)
}

func (c *ChatGPTInjector) accountIDLocked() string {
	return c.document.accountID()
}

func accountIDFromIDToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	for _, key := range []string{"chatgpt_account_id", chatGPTAuthNamespace + ".chatgpt_account_id"} {
		var value string
		if json.Unmarshal(claims[key], &value) == nil && value != "" {
			return value
		}
	}
	var namespaced map[string]json.RawMessage
	if json.Unmarshal(claims[chatGPTAuthNamespace], &namespaced) == nil {
		var value string
		if json.Unmarshal(namespaced["chatgpt_account_id"], &value) == nil {
			return value
		}
	}
	return ""
}

func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return time.Time{}
	}
	var exp float64
	if json.Unmarshal(claims["exp"], &exp) != nil || exp <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(exp), 0)
}

func samePath(a, b string) bool {
	aAbs, errA := filepath.Abs(a)
	bAbs, errB := filepath.Abs(b)
	return errA == nil && errB == nil && filepath.Clean(aAbs) == filepath.Clean(bAbs)
}

func cloneRawFields(fields map[string]json.RawMessage) map[string]json.RawMessage {
	clone := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		clone[key] = append(json.RawMessage(nil), value...)
	}
	return clone
}

func readPrivateSecretFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret file is unavailable or not private")
	}
	return os.ReadFile(path)
}

func atomicWritePrivateSecret(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("secret directory is not private")
	}

	tmp, err := os.CreateTemp(dir, ".chatgpt-auth-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// errorResponse creates an HTTP error response with plain text content.
// req must be non-nil so goproxy can read resp.Request in HTTPS/MITM paths.
func errorResponse(req *http.Request, statusCode int, message string) *http.Response {
	return &http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(message))),
		ContentLength: int64(len(message)),
		Request:       req,
	}
}

// TokenVendor intercepts the configured OAuth2 token exchanges from the
// agent and returns synthetic tokens.
//
// The agent has a stub ADC file with dummy credentials. When its auth library
// tries to exchange these for an access token (POST oauth2.googleapis.com/token),
// the proxy intercepts and returns a dummy token. The agent uses this dummy
// token in subsequent API calls, and the GCloudInjector overrides it with
// a real token before forwarding to upstream.
//
// This means the agent never sees any real credential — not the refresh token,
// not the service account key, and not even a short-lived access token.
type TokenVendor struct {
	googleEnabled   bool
	chatGPTEnabled  bool
	chatGPTInjector *ChatGPTInjector
}

// NewTokenVendor creates a token vendor.
func NewTokenVendor() *TokenVendor {
	return &TokenVendor{googleEnabled: true}
}

// NewChatGPTTokenVendor creates a vendor for the Codex ChatGPT OAuth token
// endpoint. Login-completing exchanges are forwarded to the real endpoint and
// persisted via the injector; refresh requests return synthetic values only.
func NewChatGPTTokenVendor(injector *ChatGPTInjector) *TokenVendor {
	return &TokenVendor{chatGPTEnabled: true, chatGPTInjector: injector}
}

var allowedLoginParams = map[string][]string{
	"authorization_code": {
		"grant_type", "code", "redirect_uri", "client_id", "code_verifier",
	},
	"urn:ietf:params:oauth:grant-type:device_code": {
		"grant_type", "device_code", "client_id",
	},
	"urn:ietf:params:oauth:grant-type:token-exchange": {
		"grant_type", "client_id", "requested_token", "subject_token", "subject_token_type",
	},
}

func sanitizeLoginForm(agentValues url.Values, clientID string) (url.Values, error) {
	grantType := agentValues.Get("grant_type")
	if grantType == "" {
		return nil, fmt.Errorf("missing grant_type")
	}
	allowed, known := allowedLoginParams[grantType]
	if !known {
		return nil, fmt.Errorf("unsupported grant_type %q", grantType)
	}

	allowedSet := make(map[string]bool, len(allowed))
	for _, p := range allowed {
		allowedSet[p] = true
	}
	for key := range agentValues {
		if !allowedSet[key] {
			log.Printf("LOGIN_SANITIZE stripped disallowed parameter %q from %s grant", key, grantType)
		}
	}

	sanitized := make(url.Values, len(allowed))
	for _, param := range allowed {
		if v := agentValues.Get(param); v != "" {
			sanitized.Set(param, v)
		}
	}
	sanitized.Set("client_id", clientID)
	return sanitized, nil
}

// tokenResponse covers the OAuth fields needed by Google Auth and Codex.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// IsTokenExchange returns true if the request is an OAuth2 token exchange
// to Google's token endpoint.
func IsTokenExchange(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	return req.Method == http.MethodPost && isGoogleTokenEndpoint(req)
}

func isGoogleTokenEndpoint(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	// Strip port for comparison
	return (host == "oauth2.googleapis.com" || host == "oauth2.googleapis.com:443") && req.URL.Path == "/token"
}

// IsChatGPTTokenExchange returns true only for Codex's OAuth refresh endpoint.
func IsChatGPTTokenExchange(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	return req.Method == http.MethodPost &&
		strings.EqualFold(req.URL.Hostname(), "auth.openai.com") &&
		req.URL.Path == "/oauth/token"
}

// HandleTokenExchange responds to an OAuth2 token exchange request with
// a dummy access token. The real token injection happens later via the
// GCloudInjector when the agent makes API calls to *.googleapis.com.
func (tv *TokenVendor) HandleTokenExchange(req *http.Request) *http.Response {
	if req == nil || req.URL == nil {
		log.Printf("DEFENSIVE_CHECK: HandleTokenExchange called with nil request or URL")
		return errorResponse(req, http.StatusBadRequest, "Malformed token exchange request")
	}

	var resp *tokenResponse
	if tv.googleEnabled && IsTokenExchange(req) {
		resp = &tokenResponse{
			AccessToken: "paude-proxy-managed",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
	} else if tv.chatGPTEnabled && IsChatGPTTokenExchange(req) {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			return errorResponse(req, http.StatusBadRequest, "Failed to read request body")
		}

		values, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			return errorResponse(req, http.StatusBadRequest, "Malformed form body")
		}
		grantType := values.Get("grant_type")

		if grantType == "refresh_token" {
			log.Printf("TOKEN_VEND host=%s path=%s (returned synthetic token, real injection at request time)", req.URL.Host, req.URL.Path)
			return syntheticChatGPTResponse(req)
		}
		return tv.handleLoginExchange(req, values)
	} else {
		return nil
	}

	body, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR token vendor: marshal response: %v", err)
		return errorResponse(req, http.StatusInternalServerError, "Internal token vendor error")
	}

	log.Printf("TOKEN_VEND host=%s path=%s (returned synthetic token, real injection at request time)", req.URL.Host, req.URL.Path)

	return &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func (tv *TokenVendor) handleLoginExchange(req *http.Request, agentValues url.Values) *http.Response {
	if tv.chatGPTInjector == nil {
		log.Printf("ERROR login exchange: no ChatGPT injector configured")
		return errorResponse(req, http.StatusInternalServerError, "Internal proxy error")
	}

	sanitized, err := sanitizeLoginForm(agentValues, tv.chatGPTInjector.config.ClientID)
	if err != nil {
		log.Printf("LOGIN_SANITIZE rejected request: %v", err)
		return errorResponse(req, http.StatusBadRequest, "Invalid login exchange request")
	}

	forwardReq, err := http.NewRequest(http.MethodPost, chatGPTTokenURL, strings.NewReader(sanitized.Encode()))
	if err != nil {
		log.Printf("ERROR login exchange: construct forward request")
		return errorResponse(req, http.StatusInternalServerError, "Internal proxy error")
	}
	forwardReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := tv.chatGPTInjector.config.HTTPClient
	upstreamResp, err := httpClient.Do(forwardReq)
	if err != nil {
		log.Printf("ERROR login exchange: upstream request failed")
		return errorResponse(req, http.StatusBadGateway, "Login exchange failed")
	}
	defer upstreamResp.Body.Close()

	upstreamBody, err := io.ReadAll(io.LimitReader(upstreamResp.Body, 1<<20))
	if err != nil {
		return errorResponse(req, http.StatusBadGateway, "Login exchange response unreadable")
	}

	if upstreamResp.StatusCode < http.StatusOK || upstreamResp.StatusCode >= http.StatusMultipleChoices {
		log.Printf("TOKEN_VEND host=%s path=%s (login exchange upstream returned %d, passing through to agent)", req.URL.Host, req.URL.Path, upstreamResp.StatusCode)
		ct := upstreamResp.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		return &http.Response{
			StatusCode:    upstreamResp.StatusCode,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {ct}},
			Body:          io.NopCloser(bytes.NewReader(upstreamBody)),
			ContentLength: int64(len(upstreamBody)),
			Request:       req,
		}
	}

	if err := tv.chatGPTInjector.AcceptLoginTokens(upstreamBody); err != nil {
		log.Printf("ERROR login exchange: token acceptance failed")
		return errorResponse(req, http.StatusInternalServerError, "Login token processing failed")
	}

	log.Printf("TOKEN_VEND host=%s path=%s (login exchange completed, real tokens persisted, synthetic response returned)", req.URL.Host, req.URL.Path)
	return syntheticChatGPTResponse(req)
}

func syntheticChatGPTResponse(req *http.Request) *http.Response {
	resp := &tokenResponse{
		AccessToken:  "paude-proxy-managed-access",
		RefreshToken: "paude-proxy-managed-refresh",
		IDToken:      syntheticChatGPTIDToken(),
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func syntheticChatGPTIDToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := map[string]any{
		"https://api.openai.com/auth": map[string]string{
			"chatgpt_account_id": "paude-proxy-managed-account",
		},
	}
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".paude-proxy-managed"
}

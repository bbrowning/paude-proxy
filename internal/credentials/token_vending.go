package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// errorResponse creates an HTTP error response with plain text content.
func errorResponse(statusCode int, message string) *http.Response {
	return &http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(message))),
		ContentLength: int64(len(message)),
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
	googleEnabled  bool
	chatGPTEnabled bool
}

// NewTokenVendor creates a token vendor.
func NewTokenVendor() *TokenVendor {
	return &TokenVendor{googleEnabled: true}
}

// NewChatGPTTokenVendor creates a vendor for the Codex ChatGPT OAuth token
// endpoint. The response contains only synthetic values.
func NewChatGPTTokenVendor() *TokenVendor {
	return &TokenVendor{chatGPTEnabled: true}
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
		return errorResponse(http.StatusBadRequest, "Malformed token exchange request")
	}

	var resp *tokenResponse
	if tv.googleEnabled && IsTokenExchange(req) {
		resp = &tokenResponse{
			AccessToken: "paude-proxy-managed",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
	} else if tv.chatGPTEnabled && IsChatGPTTokenExchange(req) {
		resp = &tokenResponse{
			AccessToken:  "paude-proxy-managed-access",
			RefreshToken: "paude-proxy-managed-refresh",
			IDToken:      syntheticChatGPTIDToken(),
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		}
	} else {
		return nil
	}

	body, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR token vendor: marshal response: %v", err)
		return errorResponse(http.StatusInternalServerError, "Internal token vendor error")
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

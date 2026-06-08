package credentials

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
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

// TokenVendor intercepts OAuth2 token exchange requests from the agent's
// Google Auth library and returns dummy tokens.
//
// The agent has a stub ADC file with dummy credentials. When its auth library
// tries to exchange these for an access token (POST oauth2.googleapis.com/token),
// the proxy intercepts and returns a dummy token. The agent uses this dummy
// token in subsequent API calls, and the GCloudInjector overrides it with
// a real token before forwarding to upstream.
//
// This means the agent never sees any real credential — not the refresh token,
// not the service account key, and not even a short-lived access token.
type TokenVendor struct{}

// NewTokenVendor creates a token vendor.
func NewTokenVendor() *TokenVendor {
	return &TokenVendor{}
}

// tokenResponse matches Google's OAuth2 token endpoint response format.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// IsTokenExchange returns true if the request is an OAuth2 token exchange to
// Google's token endpoint. Anthropic's token endpoint is handled separately by
// IsAnthropicTokenExchange and the refresh-intercept layer.
func IsTokenExchange(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	// Match host with or without the default :443 port suffix.
	if host == "oauth2.googleapis.com" || host == "oauth2.googleapis.com:443" {
		return req.Method == http.MethodPost && req.URL.Path == "/token"
	}
	return false
}

// IsAnthropicTokenExchange returns true if the request is an OAuth2 token
// exchange to Anthropic's token endpoint. The refresh-intercept layer uses this
// to piggyback on Claude Code's native refresh: it rewrites the request body
// with the real refresh token and replaces the response body with a dummy.
func IsAnthropicTokenExchange(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	// Match host with or without the default :443 port suffix.
	if host == "console.anthropic.com" || host == "console.anthropic.com:443" ||
		host == "platform.claude.com" || host == "platform.claude.com:443" {
		return req.Method == http.MethodPost &&
			(req.URL.Path == "/v1/oauth/token" || req.URL.Path == "/api/oauth/token")
	}
	return false
}

// HandleTokenExchange responds to an OAuth2 token exchange request with
// a dummy access token. The real token injection happens later via the
// GCloudInjector when the agent makes API calls to *.googleapis.com.
func (tv *TokenVendor) HandleTokenExchange(req *http.Request) *http.Response {
	if req == nil || req.URL == nil {
		log.Printf("DEFENSIVE_CHECK: HandleTokenExchange called with nil request or URL")
		return errorResponse(http.StatusBadRequest, "Malformed token exchange request")
	}

	resp := &tokenResponse{
		AccessToken: "paude-proxy-managed",
		ExpiresIn:   3600,
		TokenType:   "Bearer",
	}

	body, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR token vendor: marshal response: %v", err)
		return errorResponse(http.StatusInternalServerError, "Internal token vendor error")
	}

	log.Printf("TOKEN_VEND host=%s path=%s (returned dummy token, real injection at request time)", req.URL.Host, req.URL.Path)

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

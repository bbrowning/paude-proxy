package credentials

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

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

// IsTokenExchange returns true if the request is an OAuth2 token exchange
// to Google's token endpoint.
func IsTokenExchange(req *http.Request) bool {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	// Strip port for comparison
	if host == "oauth2.googleapis.com" || host == "oauth2.googleapis.com:443" {
		return req.Method == http.MethodPost && req.URL.Path == "/token"
	}
	return false
}

// HandleTokenExchange responds to an OAuth2 token exchange request with
// a dummy access token. The real token injection happens later via the
// GCloudInjector when the agent makes API calls to *.googleapis.com.
func (tv *TokenVendor) HandleTokenExchange(req *http.Request) *http.Response {
	resp := &tokenResponse{
		AccessToken: "paude-proxy-managed",
		ExpiresIn:   3600,
		TokenType:   "Bearer",
	}

	body, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR token vendor: marshal response: %v", err)
		return nil
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

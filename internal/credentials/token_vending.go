package credentials

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

// TokenVendor intercepts OAuth2 token exchange requests from the agent's
// Google Auth library and returns real tokens obtained from the proxy's ADC.
//
// The agent has a stub ADC file with dummy credentials. When its auth library
// tries to exchange these for an access token (POST oauth2.googleapis.com/token),
// the proxy intercepts the request and returns a real token instead.
//
// This prevents the agent from ever seeing the real refresh token or service
// account key, while giving it short-lived access tokens (~1 hour).
type TokenVendor struct {
	gcloud *GCloudInjector
}

// NewTokenVendor creates a token vendor backed by a GCloudInjector.
func NewTokenVendor(gcloud *GCloudInjector) *TokenVendor {
	return &TokenVendor{gcloud: gcloud}
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
// a real access token from the proxy's ADC. Returns nil if the token
// vendor is not available or token refresh fails (caller should forward
// the request to upstream in that case).
func (tv *TokenVendor) HandleTokenExchange(req *http.Request) *http.Response {
	if tv.gcloud == nil {
		log.Printf("WARN token exchange intercepted but no gcloud ADC configured")
		return nil
	}

	if err := tv.gcloud.init(); err != nil {
		log.Printf("ERROR token vendor: gcloud init failed: %v", err)
		return nil
	}

	token, err := tv.gcloud.credentials.TokenSource.Token()
	if err != nil {
		log.Printf("ERROR token vendor: token refresh failed: %v", err)
		return nil
	}

	resp := &tokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   3600,
		TokenType:   "Bearer",
	}

	body, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR token vendor: marshal response: %v", err)
		return nil
	}

	log.Printf("TOKEN_VEND host=%s path=%s (returned real token, expires_in=%d)", req.URL.Host, req.URL.Path, resp.ExpiresIn)

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

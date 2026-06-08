package proxy

import "encoding/json"

const dummyAccessToken = "sk-ant-oat01-paude-proxy-managed"
const dummyRefreshToken = "sk-ant-ort01-paude-proxy-managed"

// rewriteRefreshBody replaces refresh_token with realRefresh in a
// grant_type=refresh_token JSON body, preserving all other fields (client_id,
// etc.). Returns (newBody, true) when it was a refresh_token grant, else (orig, false).
func rewriteRefreshBody(body []byte, realRefresh string) ([]byte, bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body, false
	}
	if m["grant_type"] != "refresh_token" {
		return body, false
	}
	m["refresh_token"] = realRefresh
	out, err := json.Marshal(m)
	if err != nil {
		return body, false
	}
	return out, true
}

// parseRefreshResponse extracts tokens from an upstream refresh response.
func parseRefreshResponse(body []byte) (access, refresh string, expiresIn int, err error) {
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &r); err != nil {
		return "", "", 0, err
	}
	return r.AccessToken, r.RefreshToken, r.ExpiresIn, nil
}

// buildDummyRefreshResponseBody returns the dummy token response handed to the
// agent, with expires_in mirroring the real value so the agent's local expiry
// stays in sync with the real token.
func buildDummyRefreshResponseBody(expiresIn int) []byte {
	b, _ := json.Marshal(map[string]any{
		"access_token":  dummyAccessToken,
		"refresh_token": dummyRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
	})
	return b
}

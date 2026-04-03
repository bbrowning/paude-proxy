# Paude Proxy

MITM credential-injecting HTTP proxy for AI agent containers. Written in Go.

## What This Project Does

AI coding agents (Claude Code, Cursor, Gemini CLI) run in isolated containers. Today, API credentials are injected into those containers. This proxy removes that need: it sits between the agent container and the internet, intercepts HTTPS via MITM, and injects credentials into outgoing requests based on the destination domain. The agent never sees valid credentials.

## Build and Test

```bash
make build        # Build binary to bin/paude-proxy
make test         # Run all tests
make lint         # go vet
make docker       # Build container image with podman
```

Requires Go 1.23+. After cloning, run `go mod tidy` to resolve dependencies.

## Architecture

```
Agent Container              paude-proxy                   Internet
 (no credentials)            (has credentials)
      |                           |
      |-- CONNECT example.com --->|
      |<-- MITM cert (from CA) ---|-- real TLS to example.com
      |-- HTTP request ---------->|-- injects auth headers
      |                           |-- forwards to upstream
      |<-- response --------------|<-- upstream response
```

- Uses `github.com/elazarl/goproxy` for MITM proxy
- Uses `golang.org/x/oauth2/google` for gcloud ADC token refresh
- Loads existing CA from `PAUDE_PROXY_CA_DIR` if `ca.crt` and `ca.key` are present; otherwise generates a new self-signed ECDSA CA and writes it there. Mount this directory as a volume to persist the CA across proxy restarts.
- The CA cert must be copied to the agent container and trusted there (done by the orchestrator, not this project)

## Key Design Rules

- **Always override auth headers** — the agent has dummy placeholder credentials (e.g., `ANTHROPIC_API_KEY=paude-proxy-managed`). The proxy always replaces the auth header with real credentials, even if the agent already set one. The agent should never control which credentials are used.
- **If a credential env var is unset, pass through without injection** — no error, just no injection
- **Domain filter format must match paude's conventions**: exact (`api.example.com`), wildcard suffix (`.example.com`), regex (`~pattern`)
- **Token vending for gcloud ADC** — the agent has a stub ADC file with dummy `refresh_token`. When the agent's Google Auth library POSTs to `oauth2.googleapis.com/token`, the proxy intercepts and returns a **dummy** access token (`paude-proxy-managed`). The agent uses this dummy token in API calls, and the `GCloudInjector` overrides it with a real token at request time. The agent never sees any real credential — not the refresh token, not even a short-lived access token.
- **First matching credential route wins** — order matters in the store
- **Credential routing uses CONNECT target, never Host header** — goproxy sets `req.URL.Host` from the CONNECT target, which is what we use for domain matching. This prevents a malicious client from forging the Host header to redirect credentials.
- **The proxy must never follow redirects** — pass 3xx responses back to the client. Following redirects could leak injected credentials to a redirect target on a different domain.
- **Validate credential-domain binding at startup** — warn if a credential is configured but its domains aren't in `ALLOWED_DOMAINS`. Credentials should only be injectable for allowed domains.
- **Log all credential injections** — every time a credential is injected, log the destination domain and credential type (never the credential value). This enables auditing.
- **Source IP filtering for defense-in-depth** — `PAUDE_PROXY_ALLOWED_CLIENTS` (optional) restricts which IPs can connect. In imperative deployments (paude with Podman/Docker), the orchestrator passes the agent's IP. In GitOps/K8s deployments, NetworkPolicy is the primary control and this can be omitted. No secrets are given to the agent — source IPs can't be spoofed (enforced by CNI/container runtime).

## Security Model

The agent container is the threat actor. It can make arbitrary HTTP requests through the proxy. The proxy's job is to ensure credentials only go where they should.

**What the proxy protects against:**
- Agent reading credentials from filesystem/env (credentials only exist in the proxy container)
- Credentials sent to wrong domains (hardcoded routing table, strict suffix matching)
- Host header forgery (credential routing uses CONNECT target, not Host header)
- Redirect-based credential leakage (proxy doesn't follow redirects)
- Domain suffix confusion (`evil-openai.com` does NOT match `.openai.com`)
- Unauthorized proxy access (source IP filtering via `PAUDE_PROXY_ALLOWED_CLIENTS` + network isolation via dedicated container network or K8s NetworkPolicy)

**What the proxy does NOT protect against:**
- Agent misusing credentials for their intended service (e.g., using a GitHub PAT to push code). Mitigate with fine-grained, least-privilege tokens.
- APIs reflecting credentials in response bodies (rare, but possible in error messages). Accept as residual risk.
- DNS rebinding (low risk in container environments with controlled DNS)

## Configuration (all via env vars)

| Variable | Description | Default |
|---|---|---|
| `PAUDE_PROXY_ALLOWED_CLIENTS` | Comma-separated IPs/CIDRs allowed to connect | (empty = all) |
| `PAUDE_PROXY_LISTEN` | Listen address | `:3128` |
| `PAUDE_PROXY_CA_DIR` | Dir for generated CA cert/key | `/data/ca` |
| `PAUDE_PROXY_VERBOSE` | Verbose logging (`1`/`0`) | `0` |
| `BLOCKED_LOG_PATH` | Path for blocked-request log file | `/tmp/squid-blocked.log` |
| `PAUDE_PROXY_CREDENTIALS_CONFIG` | Path to custom credential routing JSON config | (embedded default) |
| `ALLOWED_DOMAINS` | Comma-separated allowlist (empty = all) | |
| `ALLOWED_OTEL_PORTS` | Comma-separated extra allowed ports | |
| `ANTHROPIC_API_KEY` | -> `x-api-key` for `*.anthropic.com` | |
| `OPENAI_API_KEY` | -> `Authorization: Bearer` for `*.openai.com` | |
| `CURSOR_API_KEY` | -> `Authorization: Bearer` for `*.cursor.com`, `*.cursorapi.com` | |
| `GH_TOKEN` | -> `Authorization: Bearer` for `github.com`, `*.githubusercontent.com` | |
| `GCP_ADC_JSON` | Inline gcloud ADC JSON content (preferred over file path) | |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to gcloud ADC JSON (fallback if `GCP_ADC_JSON` unset) | |

## Credential Routing Table

The default credential routing is defined in `internal/credentials/credentials.json` and embedded into the binary. It can be overridden at runtime by setting `PAUDE_PROXY_CREDENTIALS_CONFIG` to point to a custom JSON config file. See the README for the config file format.

| Domain Pattern | Header Injected | Source |
|---|---|---|
| `*.anthropic.com` | `x-api-key: <key>` | `ANTHROPIC_API_KEY` |
| `*.openai.com` | `Authorization: Bearer <key>` | `OPENAI_API_KEY` |
| `*.cursor.com`, `*.cursorapi.com` | `Authorization: Bearer <key>` | `CURSOR_API_KEY` |
| `api.github.com` | `Authorization: Bearer <pat>` | `GH_TOKEN` |
| `*.googleapis.com` | `Authorization: Bearer <token>` | gcloud ADC (auto-refresh) |

## Client Compatibility

Agent SDKs need credentials to initialize. Without them, they fail before making any HTTP request. The solution: give agents **dummy placeholder credentials** that satisfy SDK init, then the proxy overrides them with real values.

### Static API keys (Anthropic, OpenAI, Cursor, GitHub)

The orchestrator (paude) sets dummy env vars in the agent container:
```
ANTHROPIC_API_KEY=paude-proxy-managed
OPENAI_API_KEY=paude-proxy-managed
GH_TOKEN=paude-proxy-managed
```
The SDK initializes, sends requests with the dummy key in headers. The proxy **always overrides** the header with the real key before forwarding upstream.

### gcloud ADC (Vertex AI, Gemini)

The orchestrator provides a **stub ADC file** in the agent container:
```json
{
  "type": "authorized_user",
  "client_id": "paude-proxy-managed",
  "client_secret": "paude-proxy-managed",
  "refresh_token": "paude-proxy-managed"
}
```

The agent's Google Auth library reads this and POSTs to `oauth2.googleapis.com/token` to exchange the dummy refresh_token for an access token. This request goes through the proxy (HTTP_PROXY is set).

The proxy's **token vendor** intercepts this request and returns a **dummy** access token (`paude-proxy-managed`). The agent then uses this dummy token in API calls to `*.googleapis.com`. The `GCloudInjector` overrides the dummy Bearer header with a real token (from the proxy's own ADC) before forwarding to Google.

The agent never sees any real credential — not the refresh token, not the service account key, and not even a short-lived access token.

### Cursor

Cursor uses auth tokens from `~/.config/cursor/auth.json` and/or `CURSOR_API_KEY`. The orchestrator provides a dummy `CURSOR_API_KEY=paude-proxy-managed`. The proxy overrides the auth header.

### What agents see vs what's real

| What agent has | What proxy injects |
|---|---|
| `ANTHROPIC_API_KEY=paude-proxy-managed` | Real `x-api-key: sk-ant-...` |
| `OPENAI_API_KEY=paude-proxy-managed` | Real `Authorization: Bearer sk-...` |
| `GH_TOKEN=paude-proxy-managed` | Real `Authorization: Bearer ghp_...` |
| Stub ADC with dummy refresh_token | Dummy token from vendor, real token injected at API call time |

## Project Layout

- `cmd/paude-proxy/main.go` — entry point, config loading, startup validation
- `internal/credentials/credentials.json` — default credential routing config (embedded into binary via `//go:embed`)
- `internal/credentials/config.go` — config file parsing, validation, and credential store builder
- `internal/proxy/proxy.go` — core MITM proxy: CONNECT handling, domain filter, port filter, token vending intercept, credential injection, blocked logging, header suppression
- `internal/proxy/ca.go` — ECDSA P-256 CA cert/key generation
- `internal/proxy/ca_test.go` — tests for CA generation and file writing
- `internal/filter/domains.go` — domain allowlist matching (exact, `.suffix`, `~regex`)
- `internal/filter/domains_test.go` — tests for all domain matching patterns
- `internal/credentials/store.go` — credential route store, domain-to-injector matching, injection logging
- `internal/credentials/store_test.go` — tests for routing, override behavior, first-match-wins
- `internal/credentials/static.go` — always-override injectors: Bearer, API key, generic header
- `internal/credentials/gcloud.go` — gcloud ADC OAuth2 token refresh via `golang.org/x/oauth2/google`
- `internal/credentials/token_vending.go` — intercepts `POST oauth2.googleapis.com/token`, returns dummy tokens
- `Dockerfile` — multi-stage build (Go builder + CentOS Stream 10 runtime with dnsmasq + tini)
- `entrypoint.sh` — starts dnsmasq for DNS forwarding, then runs paude-proxy

## Current Status

All source code is implemented, compiles cleanly, and all tests pass. Features:
- MITM HTTPS interception with generated ECDSA CA
- Credential injection (Anthropic, OpenAI, Cursor, GitHub, gcloud ADC)
- Domain allowlist filtering (exact, wildcard suffix, regex)
- Port filtering (Safe_ports/SSL_ports, matching squid behavior)
- Blocked-request logging to `/tmp/squid-blocked.log` (compatible with paude's `proxy_log.py` parser)
- Token vending for gcloud ADC (returns dummy tokens to agent, injects real ones)
- Proxy identity header suppression (strips Via, X-Forwarded-For)
- DNS forwarding via dnsmasq
- OpenShift-compatible container image

## Consumer: Paude

This proxy is consumed by the [paude](https://github.com/bbrowning/paude) project. Paude will:
- Run this as a separate container alongside agent containers (NOT a sidecar — separate container like the current squid proxy)
- Copy the CA cert from this container to the agent container via `podman cp` / `oc cp`
- Pass real credential env vars to this container (not the agent)
- Set dummy placeholder env vars in the agent container (e.g., `ANTHROPIC_API_KEY=paude-proxy-managed`)
- Write a stub ADC JSON file to the agent container (for gcloud auth flow)
- Set `HTTP_PROXY`/`HTTPS_PROXY` on the agent container pointing here
- Set `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` in the agent for CA trust

A doc in the paude repo (`docs/AUTH_PROXY_INTEGRATION.md`) describes the integration steps on the paude side.

## Testing Tips

For manual testing without a full container setup:
```bash
# Terminal 1: run the proxy with domain filtering
ALLOWED_DOMAINS=httpbin.org,.openai.com PAUDE_PROXY_CA_DIR=/tmp/paude-proxy-ca make run

# Terminal 2: test with curl
# Use --proxy-cacert to trust the generated CA:
curl --proxy-cacert /tmp/paude-proxy-ca/ca.crt -x http://localhost:3128 https://httpbin.org/headers

# Test domain blocking:
curl --proxy-cacert /tmp/paude-proxy-ca/ca.crt -x http://localhost:3128 https://evil.com
# Should fail with connection rejected

# Test source IP filtering:
PAUDE_PROXY_ALLOWED_CLIENTS=127.0.0.1 ALLOWED_DOMAINS=httpbin.org PAUDE_PROXY_CA_DIR=/tmp/paude-proxy-ca make run
# Requests from 127.0.0.1 succeed; requests from other IPs are rejected

# Test credential injection (start proxy with a key):
OPENAI_API_KEY=sk-test123 ALLOWED_DOMAINS=httpbin.org,.openai.com PAUDE_PROXY_CA_DIR=/tmp/paude-proxy-ca make run
# Requests to *.openai.com will have Authorization: Bearer sk-test123 injected
# Requests to httpbin.org will NOT have credentials (no matching route)

# Test always-override behavior:
# Even if curl sends -H "Authorization: Bearer dummy", the proxy replaces it
curl --proxy-cacert /tmp/paude-proxy-ca/ca.crt -x http://localhost:3128 \
  -H "Authorization: Bearer dummy" https://api.openai.com/v1/models
# The upstream receives "Bearer sk-test123", not "Bearer dummy"

# Test gcloud ADC (requires a real ADC file):
GOOGLE_APPLICATION_CREDENTIALS=/path/to/adc.json ALLOWED_DOMAINS=.googleapis.com PAUDE_PROXY_CA_DIR=/tmp/paude-proxy-ca make run
# Requests to *.googleapis.com get a real OAuth2 Bearer token
```

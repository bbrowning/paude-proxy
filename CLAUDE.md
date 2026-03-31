# Auth Proxy

MITM credential-injecting HTTP proxy for AI agent containers. Written in Go.

## What This Project Does

AI coding agents (Claude Code, Cursor, Gemini CLI) run in isolated containers. Today, API credentials are injected into those containers. This proxy removes that need: it sits between the agent container and the internet, intercepts HTTPS via MITM, and injects credentials into outgoing requests based on the destination domain. The agent never sees valid credentials.

## Build and Test

```bash
make build        # Build binary to bin/auth-proxy
make test         # Run all tests
make lint         # go vet
make docker       # Build container image with podman
```

Requires Go 1.23+. After cloning, run `go mod tidy` to resolve dependencies.

## Architecture

```
Agent Container              auth-proxy                    Internet
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
- Generates a self-signed ECDSA CA at startup, writes to `AUTH_PROXY_CA_DIR`
- The CA cert must be copied to the agent container and trusted there (done by the orchestrator, not this project)

## Key Design Rules

- **Only inject if the header is NOT already present** — allows agent-side overrides
- **If a credential env var is unset, pass through without injection** — no error, just no injection
- **Domain filter format must match paude's conventions**: exact (`api.example.com`), wildcard suffix (`.example.com`), regex (`~pattern`)
- **OAuth endpoints (`accounts.google.com`, `oauth2.googleapis.com`) must NOT have credentials injected** — the OAuth flow handles its own auth. Only inject Bearer tokens for `*.googleapis.com` API calls.
- **First matching credential route wins** — order matters in the store

## Configuration (all via env vars)

| Variable | Description | Default |
|---|---|---|
| `AUTH_PROXY_LISTEN` | Listen address | `:3128` |
| `AUTH_PROXY_CA_DIR` | Dir for generated CA cert/key | `/data/ca` |
| `AUTH_PROXY_VERBOSE` | Verbose logging (`1`/`0`) | `0` |
| `ALLOWED_DOMAINS` | Comma-separated allowlist (empty = all) | |
| `ANTHROPIC_API_KEY` | -> `x-api-key` for `*.anthropic.com` | |
| `OPENAI_API_KEY` | -> `Authorization: Bearer` for `*.openai.com` | |
| `CURSOR_API_KEY` | -> `Authorization: Bearer` for `*.cursor.com`, `*.cursorapi.com` | |
| `GH_TOKEN` | -> `Authorization: token` for `github.com`, `*.githubusercontent.com` | |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to gcloud ADC JSON | |

## Credential Routing Table

| Domain Pattern | Header Injected | Source |
|---|---|---|
| `*.anthropic.com` | `x-api-key: <key>` | `ANTHROPIC_API_KEY` |
| `*.openai.com` | `Authorization: Bearer <key>` | `OPENAI_API_KEY` |
| `*.cursor.com`, `*.cursorapi.com` | `Authorization: Bearer <key>` | `CURSOR_API_KEY` |
| `github.com`, `api.github.com` | `Authorization: token <pat>` | `GH_TOKEN` |
| `*.githubusercontent.com` | `Authorization: token <pat>` | `GH_TOKEN` |
| `*.googleapis.com` | `Authorization: Bearer <token>` | gcloud ADC (auto-refresh) |

## Project Layout

- `cmd/auth-proxy/main.go` — entry point, config loading, credential store assembly
- `internal/proxy/proxy.go` — core MITM proxy setup using goproxy
- `internal/proxy/ca.go` — CA cert/key generation
- `internal/filter/domains.go` — domain allowlist matching
- `internal/credentials/store.go` — credential route store, domain-to-injector matching
- `internal/credentials/static.go` — static credential injectors (Bearer, API key, GitHub token)
- `internal/credentials/gcloud.go` — gcloud ADC OAuth2 token refresh
- `Dockerfile` — multi-stage build (Go builder + CentOS Stream 10 runtime with dnsmasq + tini)
- `entrypoint.sh` — starts dnsmasq for DNS forwarding, then runs auth-proxy

## Current Status

**Phase 1 (in progress):** Core proxy with domain filtering + MITM + credential injection is scaffolded. Needs:

1. `go mod tidy` to resolve full dependency tree (go.sum doesn't exist yet)
2. Build and fix any compilation errors
3. Run tests, fix failures
4. Test with a real HTTPS request through the proxy (e.g., `curl -x http://localhost:3128 https://httpbin.org/get`)
5. Test MITM works: agent trusts the CA cert, proxy can read/modify HTTPS traffic
6. Test credential injection: set `OPENAI_API_KEY=test`, verify it appears in requests to `api.openai.com`
7. Test domain filtering: verify blocked domains return 403
8. Test gcloud ADC token refresh with a real ADC JSON file

## Consumer: Paude

This proxy is consumed by the [paude](https://github.com/paude-group/paude) project. Paude will:
- Run this as a separate container alongside agent containers
- Copy the CA cert from this container to the agent container via `podman cp` / `oc cp`
- Pass credential env vars to this container (not the agent)
- Set `HTTP_PROXY`/`HTTPS_PROXY` on the agent container pointing here

A doc in the paude repo (`docs/AUTH_PROXY_INTEGRATION.md`) describes the integration work needed on the paude side.

## Testing Tips

For manual testing without a full container setup:
```bash
# Terminal 1: run the proxy
ALLOWED_DOMAINS=httpbin.org,.openai.com AUTH_PROXY_CA_DIR=/tmp/auth-proxy-ca make run

# Terminal 2: test with curl (after trusting the CA)
# First, trust the CA cert:
sudo cp /tmp/auth-proxy-ca/ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust
# Or use --proxy-cacert:
curl --proxy-cacert /tmp/auth-proxy-ca/ca.crt -x http://localhost:3128 https://httpbin.org/headers

# Test domain blocking:
curl -x http://localhost:3128 https://evil.com  # should fail

# Test credential injection:
OPENAI_API_KEY=sk-test ALLOWED_DOMAINS=.openai.com AUTH_PROXY_CA_DIR=/tmp/auth-proxy-ca make run
# Then check headers at httpbin (temporarily add to allowed domains)
```

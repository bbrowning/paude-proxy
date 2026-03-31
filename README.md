# paude-proxy

A MITM credential-injecting HTTP proxy for AI agent containers. Intercepts HTTPS traffic, injects API credentials based on destination domain, and enforces domain allowlists.

Designed to keep credentials out of AI agent containers while allowing agents to make authenticated API calls. The agent never sees any real credential.

## Features

- **MITM proxy** — Intercepts HTTPS via generated CA certificate using [goproxy](https://github.com/elazarl/goproxy)
- **Credential injection** — Always overrides auth headers with real credentials based on destination domain
- **Domain filtering** — Allowlist-based egress control (replaces squid for AI agent use cases)
- **gcloud ADC** — OAuth2 token refresh from Application Default Credentials via [golang.org/x/oauth2/google](https://pkg.go.dev/golang.org/x/oauth2/google)
- **Token vending** — Intercepts OAuth2 token exchanges, returns dummy tokens (real injection at request time)
- **Static API keys** — Supports Anthropic, OpenAI, Cursor, GitHub PAT injection

## How It Works

The agent container has dummy placeholder credentials (`ANTHROPIC_API_KEY=paude-proxy-managed`, stub ADC file with dummy refresh_token). The proxy always overrides auth headers with real credentials before forwarding to upstream.

```
Agent Container              paude-proxy                   Internet
 (dummy credentials)         (real credentials)
      |                           |
      |-- CONNECT api.openai.com ->|
      |<-- MITM cert --------------|-- TLS to api.openai.com
      |-- GET /v1/completions ---->|
      |   x-api-key: paude-proxy  |-- overrides with real key
      |                           |-- x-api-key: sk-ant-REAL
      |<-- response --------------|<-- response from upstream
```

For gcloud/Vertex AI, the agent's Google Auth library tries to exchange a dummy refresh_token. The proxy intercepts and returns a dummy access token. When the agent then calls `*.googleapis.com` with that dummy token, the proxy overrides it with a real OAuth2 token.

## Configuration

All configuration via environment variables:

| Variable | Description | Default |
|---|---|---|
| `PAUDE_PROXY_LISTEN` | Listen address | `:3128` |
| `PAUDE_PROXY_CA_DIR` | Directory for generated CA cert/key | `/data/ca` |
| `PAUDE_PROXY_VERBOSE` | Enable verbose logging | `0` |
| `ALLOWED_DOMAINS` | Comma-separated domain allowlist (empty = allow all) | |
| `ANTHROPIC_API_KEY` | Injected as `x-api-key` for `*.anthropic.com` | |
| `OPENAI_API_KEY` | Injected as `Authorization: Bearer` for `*.openai.com` | |
| `CURSOR_API_KEY` | Injected as `Authorization: Bearer` for `*.cursor.com` | |
| `GH_TOKEN` | Injected as `Authorization: token` for `github.com` | |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to gcloud ADC JSON file | |

### Domain Allowlist Format

The `ALLOWED_DOMAINS` variable supports three formats:

- **Exact**: `api.example.com` — matches only `api.example.com`
- **Wildcard suffix**: `.example.com` — matches `example.com` and `*.example.com`
- **Regex**: `~pattern` — matches hostnames against the regex

Example: `github.com,.openai.com,~aiplatform\.googleapis\.com$`

## Building

```bash
make build        # Build binary
make test         # Run tests
make lint         # go vet
make docker       # Build container image
```

Requires Go 1.23+. After cloning, run `go mod tidy` to resolve dependencies.

## CA Certificate

The proxy generates a CA certificate at startup in `PAUDE_PROXY_CA_DIR`. This certificate must be trusted by the agent container:

```bash
# Copy CA cert from proxy container to agent container
podman cp proxy:/data/ca/ca.crt /tmp/ca.crt
podman cp /tmp/ca.crt agent:/etc/pki/ca-trust/source/anchors/paude-proxy-ca.crt
podman exec agent update-ca-trust

# For Node.js agents (Claude Code, Cursor, OpenClaw), also set:
# NODE_EXTRA_CA_CERTS=/etc/pki/ca-trust/source/anchors/paude-proxy-ca.crt
# For Python tools (pip, requests), set:
# SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
# REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
```

## Security Model

The agent container is the threat actor. The proxy ensures credentials only go where they should.

**Protected against:** credential reading from filesystem/env, credentials to wrong domains, Host header forgery, redirect-based leakage, domain suffix confusion.

**Not protected against:** agent misusing credentials for their intended service (mitigate with least-privilege tokens), APIs reflecting credentials in responses (rare).

See `CLAUDE.md` for the full security analysis.

## License

Apache-2.0

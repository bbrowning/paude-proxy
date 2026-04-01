# paude-proxy

**Keep your API keys out of untrusted code.** paude-proxy is a credential-injecting HTTPS proxy — it holds your real API keys and injects them into outgoing requests based on the destination domain. Your application sends requests with dummy credentials; the proxy swaps in the real ones before they hit the wire. The application never sees, stores, or can exfiltrate valid credentials.

```
Your app                     paude-proxy                   api.openai.com
 (no real credentials)       (has real credentials)
      |                           |
      |-- Authorization: dummy -->|-- Authorization: Bearer sk-REAL-KEY
      |                           |-- forwards to upstream
      |<-- response --------------|<-- upstream response
```

This is especially useful for **AI coding agents** (Claude Code, Cursor, Gemini CLI) running in sandboxed containers, but works for any scenario where you want to broker API credentials without exposing them to the calling code.

## Quick Start

Requires Go 1.23+.

```bash
# Build
make build

# Start the proxy with your real OpenAI key
OPENAI_API_KEY=sk-your-real-key \
ALLOWED_DOMAINS=.openai.com \
PAUDE_PROXY_CA_DIR=/tmp/proxy-ca \
./bin/paude-proxy
```

In another terminal:

```bash
# Make a request through the proxy — your real key is injected automatically
curl --proxy-cacert /tmp/proxy-ca/ca.crt \
     -x http://localhost:3128 \
     https://api.openai.com/v1/models

# The request arrives at OpenAI with "Authorization: Bearer sk-your-real-key"
# even though curl never knew the real key
```

That's it. Any HTTPS client that speaks `HTTP CONNECT` can use the proxy.

## How It Works

paude-proxy is a man-in-the-middle (MITM) HTTPS proxy built on [goproxy](https://github.com/elazarl/goproxy). When a client connects:

1. Client sends `CONNECT api.openai.com:443`
2. Proxy terminates TLS using a generated CA certificate (the client must trust this CA)
3. Client sends the HTTP request (with dummy or no credentials)
4. Proxy looks up the destination domain in its credential routing table
5. If a match is found, the proxy **replaces** the auth header with real credentials
6. Proxy forwards the request over a new TLS connection to the real upstream
7. Response is passed back to the client unmodified

The proxy **always overrides** auth headers — it never trusts what the client sends. This is by design: the client should have dummy placeholder credentials that satisfy SDK initialization, and the proxy replaces them with real values.

## Standalone Usage Examples

### Multiple providers at once

```bash
ANTHROPIC_API_KEY=sk-ant-real-key \
OPENAI_API_KEY=sk-real-key \
GH_TOKEN=ghp_real-token \
ALLOWED_DOMAINS=.anthropic.com,.openai.com,github.com,.githubusercontent.com \
PAUDE_PROXY_CA_DIR=/tmp/proxy-ca \
./bin/paude-proxy
```

Requests to `*.anthropic.com` get `x-api-key: sk-ant-real-key`. Requests to `*.openai.com` get `Authorization: Bearer sk-real-key`. Requests to `github.com` get `Authorization: token ghp_real-token`. Requests to any other domain are blocked by the domain filter.

### Routing any application through the proxy

Set the standard proxy environment variables so your application routes traffic through paude-proxy:

```bash
export HTTP_PROXY=http://localhost:3128
export HTTPS_PROXY=http://localhost:3128

# Your app can use dummy credentials — the proxy injects the real ones
export ANTHROPIC_API_KEY=paude-proxy-managed
export OPENAI_API_KEY=paude-proxy-managed

# Run your application
python my_agent.py
```

The application initializes SDKs with the dummy keys (satisfying any client-side validation), sends requests through the proxy, and the proxy injects real credentials.

### Trusting the CA certificate

Since the proxy terminates TLS, clients must trust the generated CA. The CA cert is written to `$PAUDE_PROXY_CA_DIR/ca.crt` at startup.

**System-wide (RHEL/CentOS/Fedora):**
```bash
cp /tmp/proxy-ca/ca.crt /etc/pki/ca-trust/source/anchors/paude-proxy.crt
update-ca-trust
```

**System-wide (Ubuntu/Debian):**
```bash
cp /tmp/proxy-ca/ca.crt /usr/local/share/ca-certificates/paude-proxy.crt
update-ca-certificates
```

**Per-runtime (no root required):**
```bash
# Node.js
export NODE_EXTRA_CA_CERTS=/tmp/proxy-ca/ca.crt

# Python (requests, pip, httpx)
export REQUESTS_CA_BUNDLE=/tmp/proxy-ca/ca.crt
export SSL_CERT_FILE=/tmp/proxy-ca/ca.crt

# Go
export SSL_CERT_FILE=/tmp/proxy-ca/ca.crt

# curl
curl --proxy-cacert /tmp/proxy-ca/ca.crt -x http://localhost:3128 https://example.com
```

### Container deployment (Docker/Podman)

Run the proxy alongside an application container, sharing the CA cert via a volume:

```bash
# Create a shared volume for the CA cert
podman volume create proxy-ca

# Start the proxy with real credentials
podman run -d --name proxy \
  -e ANTHROPIC_API_KEY=sk-ant-real-key \
  -e OPENAI_API_KEY=sk-real-key \
  -e ALLOWED_DOMAINS=.anthropic.com,.openai.com \
  -e PAUDE_PROXY_CA_DIR=/data/ca \
  -v proxy-ca:/data/ca \
  -p 3128:3128 \
  paude-proxy:latest

# Start your application container — no real credentials needed
podman run -d --name my-app \
  -e HTTP_PROXY=http://proxy:3128 \
  -e HTTPS_PROXY=http://proxy:3128 \
  -e ANTHROPIC_API_KEY=paude-proxy-managed \
  -e NODE_EXTRA_CA_CERTS=/ca/ca.crt \
  -v proxy-ca:/ca:ro \
  my-app-image
```

The application container has no real API keys — only dummy placeholders. The proxy container holds the real credentials and injects them.

### Restricting client access

Use `PAUDE_PROXY_ALLOWED_CLIENTS` to restrict which IPs can connect to the proxy:

```bash
# Only allow connections from 10.0.0.5
PAUDE_PROXY_ALLOWED_CLIENTS=10.0.0.5 \
OPENAI_API_KEY=sk-real-key \
PAUDE_PROXY_CA_DIR=/tmp/proxy-ca \
./bin/paude-proxy
```

This prevents other containers or processes on the network from using the proxy to get credential injection. For container environments, network isolation (dedicated networks or Kubernetes NetworkPolicy) is the primary access control; source IP filtering is an additional layer.

## Credential Routing Table

| Env Var | Domain Pattern | Header Injected |
|---|---|---|
| `ANTHROPIC_API_KEY` | `*.anthropic.com` | `x-api-key: <key>` |
| `OPENAI_API_KEY` | `*.openai.com` | `Authorization: Bearer <key>` |
| `CURSOR_API_KEY` | `*.cursor.com`, `*.cursorapi.com` | `Authorization: Bearer <key>` |
| `GH_TOKEN` | `github.com`, `api.github.com`, `*.githubusercontent.com` | `Authorization: token <pat>` |
| `GOOGLE_APPLICATION_CREDENTIALS` | `*.googleapis.com` | `Authorization: Bearer <token>` (auto-refreshed OAuth2) |

Only set the env vars for the providers you need. If an env var is unset, the proxy passes requests to that domain through without credential injection.

## Configuration

All configuration is via environment variables:

| Variable | Description | Default |
|---|---|---|
| `PAUDE_PROXY_LISTEN` | Listen address | `:3128` |
| `PAUDE_PROXY_CA_DIR` | Directory for CA cert/key (persists across restarts if mounted) | `/data/ca` |
| `PAUDE_PROXY_VERBOSE` | Enable verbose logging (`1`/`0`) | `0` |
| `PAUDE_PROXY_ALLOWED_CLIENTS` | Comma-separated IPs/CIDRs allowed to connect | (all) |
| `ALLOWED_DOMAINS` | Comma-separated domain allowlist (empty = allow all) | |
| `ALLOWED_OTEL_PORTS` | Comma-separated extra allowed ports | |
| `BLOCKED_LOG_PATH` | Path for blocked-request log file | `/tmp/squid-blocked.log` |

### Domain Allowlist Format

`ALLOWED_DOMAINS` supports three formats:

- **Exact**: `api.example.com` — matches only `api.example.com`
- **Wildcard suffix**: `.example.com` — matches `example.com` and all subdomains
- **Regex**: `~pattern` — matches hostnames against the regex

Example: `github.com,.openai.com,~aiplatform\.googleapis\.com$`

### gcloud ADC (Vertex AI / Gemini)

For Google Cloud APIs, the proxy uses a two-step approach:

1. **Token vending**: The client has a stub ADC file with a dummy `refresh_token`. When its Google Auth library POSTs to `oauth2.googleapis.com/token`, the proxy intercepts and returns a dummy access token.
2. **Credential injection**: When the client calls `*.googleapis.com` with the dummy Bearer token, the proxy replaces it with a real OAuth2 token from its own ADC.

The client never sees any real credential — not the refresh token, not even a short-lived access token.

## Building

```bash
make build        # Build binary to bin/paude-proxy
make test         # Run all tests
make lint         # go vet
make docker       # Build container image with podman
make run          # Build and run locally
```

Requires Go 1.23+. After cloning, run `go mod tidy` to resolve dependencies.

## Security Model

The proxy is designed for scenarios where the client is **untrusted** (e.g., an AI agent that could be prompt-injected into attempting credential exfiltration). It protects against:

- **Credential theft from filesystem/env** — real credentials only exist in the proxy process, never in the client's environment
- **Credentials sent to wrong domains** — hardcoded routing table with strict suffix matching (`evil-openai.com` does NOT match `.openai.com`)
- **Host header forgery** — credential routing uses the CONNECT target (from the TCP connection), not the Host header
- **Redirect-based credential leakage** — proxy never follows redirects; 3xx responses pass through to the client
- **Unauthorized proxy access** — source IP filtering + network isolation

**Not in scope**: preventing the client from misusing credentials for their intended service (e.g., using a GitHub PAT to push code). Mitigate with fine-grained, least-privilege tokens.

## Integration with paude

This proxy was built for the [paude](https://github.com/bbrowning/paude) project, which orchestrates AI coding agents in containers. paude handles:

- Running the proxy as a separate container alongside agent containers
- Copying the CA cert to agent containers and configuring trust
- Setting dummy placeholder credentials in agent containers
- Writing stub ADC files for gcloud auth flow

See [`docs/PAUDE_INTEGRATION.md`](docs/PAUDE_INTEGRATION.md) for integration details.

## Why This Over Alternatives

- **[Aegis](https://github.com/getaegis/aegis)** — TypeScript, static API keys only, no gcloud ADC, no MITM
- **Envoy + Go filter** — MITM forward proxy with dynamic cert generation is complex in Envoy; goproxy is purpose-built for this
- **Squid with ssl-bump** — Would need ICAP/eCAP adapter for credential injection; much more complex for the same result

## License

MIT — see [LICENSE](LICENSE)

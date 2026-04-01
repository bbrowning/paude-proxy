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
| `PAUDE_PROXY_ALLOWED_CLIENTS` | Comma-separated IPs/CIDRs allowed to connect | (all) |
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

The agent container is the threat actor. It can make arbitrary HTTP requests through the proxy. The proxy ensures credentials only go where they should.

### What the proxy protects against

- **Credential theft** — credentials only exist in the proxy container, never in the agent's filesystem or environment
- **Credentials to wrong domains** — hardcoded routing table with strict suffix matching (`evil-openai.com` does NOT match `.openai.com`)
- **Host header forgery** — credential routing uses the CONNECT target (set from the TCP connection), not the Host header
- **Redirect-based leakage** — proxy never follows redirects; 3xx responses are passed back to the client
- **Unauthorized proxy access** — source IP filtering + network isolation (see below)

### What the proxy does NOT protect against

- Agent misusing credentials for their intended service (e.g., using a GitHub PAT to push malicious code). Mitigate with fine-grained, least-privilege tokens.
- APIs reflecting credentials in response bodies (rare, but possible in error messages). Accept as residual risk.

### Proxy Access Control

The proxy injects real API credentials into requests. Preventing unauthorized containers from using the proxy is critical — any container that can connect gets credential injection for free.

**Network isolation** is the primary control:

| Environment | Mechanism |
|---|---|
| Podman/Docker | Dedicated network per session — only proxy + agent containers on the network |
| Kubernetes/OpenShift | NetworkPolicy — proxy ingress restricted to agent pods by label selector |

**Source IP filtering** (`PAUDE_PROXY_ALLOWED_CLIENTS`) provides optional defense-in-depth. The orchestrator passes the agent container's IP to the proxy; connections from other IPs are rejected.

#### Why not a shared secret / proxy auth token?

The agent is fundamentally untrusted. Any secret given to the agent (auth token, client certificate, etc.) can be exfiltrated — the agent can read its own environment variables and files, and could send the secret to any allowed domain. In a demo or adversarial scenario, users can prompt the agent to reveal all its secrets.

Source IP filtering avoids this entirely: the agent's source IP is enforced by the container runtime / CNI and cannot be spoofed or exfiltrated in a useful way. There is no secret for the agent to reveal.

#### Deployment models

**Imperative (paude with Podman/Docker):**
1. Create a dedicated network per session
2. Create agent container, get its IP (or assign a static IP with `--ip`)
3. Create proxy container with `PAUDE_PROXY_ALLOWED_CLIENTS=<agent-ip>`
4. Both controls active: network isolation + source IP filtering

**Declarative (GitOps with Kubernetes):**
1. Declare proxy and agent pods with matching labels
2. Declare NetworkPolicy restricting proxy ingress to agent pods
3. Pre-generate CA cert as a K8s Secret, mounted into both pods
4. No `PAUDE_PROXY_ALLOWED_CLIENTS` needed — NetworkPolicy handles access control
5. No startup ordering dependency

## Why This Over Alternatives

- **[Aegis](https://github.com/getaegis/aegis)** — TypeScript, static API keys only, no gcloud ADC/Vertex AI, no MITM. Doesn't meet requirements.
- **[OpenShell router](https://github.com/NVIDIA/OpenShell)** — Rust, internal component, static API keys only, not standalone.
- **Envoy + Go filter** — MITM forward proxy with dynamic cert generation is complex in Envoy (SDS, internal listeners, CONNECT handling). goproxy is purpose-built for this. Envoy adds ~60-100MB image size vs ~15MB for our static binary.
- **Squid with ssl-bump** — Would need ICAP/eCAP adapter for credential injection. Much more complex config for the same result.

## License

Apache-2.0

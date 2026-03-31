# auth-proxy

A MITM credential-injecting HTTP proxy for AI agent containers. Intercepts HTTPS traffic, injects API credentials based on destination domain, and enforces domain allowlists.

Designed to keep credentials out of AI agent containers while allowing agents to make authenticated API calls.

## Features

- **MITM proxy** — Intercepts HTTPS via generated CA certificate
- **Credential injection** — Injects API keys and OAuth tokens into outgoing requests based on destination domain
- **Domain filtering** — Allowlist-based egress control (replaces squid for AI agent use cases)
- **gcloud ADC** — Automatic OAuth2 token refresh from Application Default Credentials
- **Static API keys** — Supports Anthropic, OpenAI, Cursor, GitHub PAT injection

## How It Works

```
Agent Container              auth-proxy                    Internet
 (no credentials)            (has credentials)
      |                           |
      |-- CONNECT api.openai.com ->|
      |<-- MITM cert --------------|-- TLS to api.openai.com
      |-- GET /v1/completions ---->|-- injects Authorization: Bearer <key>
      |                           |-- forwards request
      |<-- response --------------|<-- response from upstream
```

The agent container sets `HTTP_PROXY`/`HTTPS_PROXY` pointing to auth-proxy. The proxy generates a CA certificate at startup that must be trusted by the agent container.

## Configuration

All configuration via environment variables:

| Variable | Description | Default |
|---|---|---|
| `AUTH_PROXY_LISTEN` | Listen address | `:3128` |
| `AUTH_PROXY_CA_DIR` | Directory for generated CA cert/key | `/data/ca` |
| `AUTH_PROXY_VERBOSE` | Enable verbose logging | `0` |
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
make docker       # Build container image
```

## CA Certificate

The proxy generates a CA certificate at startup in `AUTH_PROXY_CA_DIR`. This certificate must be trusted by the agent container:

```bash
# Copy CA cert from proxy container to agent container
podman cp proxy:/data/ca/ca.crt /tmp/ca.crt
podman cp /tmp/ca.crt agent:/etc/pki/ca-trust/source/anchors/auth-proxy-ca.crt
podman exec agent update-ca-trust

# For Node.js agents, also set:
# NODE_EXTRA_CA_CERTS=/etc/pki/ca-trust/source/anchors/auth-proxy-ca.crt
```

## License

Apache-2.0

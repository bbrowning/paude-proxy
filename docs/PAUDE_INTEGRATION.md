# Integrating paude-proxy into paude

Notes for replacing the squid proxy in paude with paude-proxy (this project).

## What changes

Squid is a passthrough proxy — it filters domains but never sees HTTPS request content. paude-proxy is a MITM proxy — it terminates TLS, injects credentials into request headers, and re-encrypts to upstream. This means:

1. **Credentials move from agent container to proxy container.** Today paude injects real API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.) into the agent container. With paude-proxy, real credentials go to the proxy container and the agent gets dummy placeholders.

2. **The agent must trust the proxy's CA.** paude-proxy generates a CA cert at startup in `/data/ca/ca.crt` (or reuses an existing one if the files are already present). This cert must be copied to the agent container and trusted there.

3. **gcloud ADC needs a stub file in the agent.** Instead of giving the agent real ADC credentials, the agent gets a stub ADC JSON file with dummy values. The proxy handles real token refresh.

## Changes needed in paude

### 1. Proxy image reference

Replace the squid proxy image with the paude-proxy image. The image name/tag is stored in the `paude.io/proxy-image` label and passed to `ProxyRunner.create_session_proxy()`.

The paude-proxy Dockerfile builds a CentOS Stream 10 image with the Go binary, dnsmasq, and tini — same base OS and init setup as the current squid image.

### 2. Pass credentials to proxy container, not agent

**Current flow** (in `proxy_runner.py:_build_env_args` and `backend.py:create_session`):
- Real credentials go to agent container via `build_session_env()` / `build_secret_environment_from_config()` / Podman secrets
- Proxy container gets only `ALLOWED_DOMAINS`, `ALLOWED_DOMAIN_ACLS`, `SQUID_DNS`, `ALLOWED_OTEL_PORTS`

**New flow:**
- Proxy container gets real credentials as env vars:
  - `ANTHROPIC_API_KEY` — real key
  - `OPENAI_API_KEY` — real key
  - `CURSOR_API_KEY` — real key
  - `GH_TOKEN` — real GitHub PAT
  - `GOOGLE_APPLICATION_CREDENTIALS` — path to real ADC JSON (mount or inject the file)
- Proxy container keeps: `ALLOWED_DOMAINS`, `SQUID_DNS`, `ALLOWED_OTEL_PORTS`
- Agent container gets dummy placeholders instead of real credentials:
  - `ANTHROPIC_API_KEY=paude-proxy-managed`
  - `OPENAI_API_KEY=paude-proxy-managed`
  - `CURSOR_API_KEY=paude-proxy-managed`
  - `GH_TOKEN=paude-proxy-managed`

Which credentials to pass depends on which are set in the host environment. Only pass what's available — paude-proxy ignores unset env vars and passes requests through without injection.

**Where to change:**
- `proxy_runner.py:_build_env_args()` — add credential env vars to the proxy container's `-e` args
- `backends/podman/backend.py:_ensure_gcp_credentials()` — mount/inject ADC into proxy container instead of (or in addition to) agent container
- `backends/shared.py:build_session_env()` — replace real credential values with `paude-proxy-managed` for agent container
- `providers/base.py` — the `secret_env_vars` lists (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) define what to redirect; these same vars should now go to the proxy container and get dummy values in the agent

### 3. CA certificate distribution

paude-proxy generates a CA cert+key on first startup and writes them to `PAUDE_PROXY_CA_DIR` (default `/data/ca`). On subsequent startups, if `ca.crt` and `ca.key` already exist in that directory, they are reused. This means:

- **Mount `/data/ca` as a volume** on the proxy container. The CA persists across proxy restarts and recreations (e.g., `paude allowed-domains replace`), so the agent only needs the cert copied once per session.
- If you need to force a new CA, delete the volume or the files within it.

**Steps (after proxy start, before agent start):**

```python
# Copy CA cert from proxy to agent container
engine.run("cp", f"{proxy_name}:/data/ca/ca.crt", "/tmp/paude-proxy-ca.crt")
engine.run("cp", "/tmp/paude-proxy-ca.crt", f"{agent_name}:/etc/pki/ca-trust/source/anchors/paude-proxy-ca.crt")
runner.exec_in_container(agent_name, ["update-ca-trust"])
```

Since the CA is stable across restarts (when `/data/ca` is a volume), this copy only needs to happen once at session creation. Proxy recreations (domain updates) reuse the same CA, so no re-copy is needed.

**Additional env vars for the agent container** (set in `build_session_env`):

```python
# For Node.js-based agents (Claude Code, Cursor, OpenClaw)
env["NODE_EXTRA_CA_CERTS"] = "/etc/pki/ca-trust/source/anchors/paude-proxy-ca.crt"

# For Python-based tools (pip, requests, httpx)
env["REQUESTS_CA_BUNDLE"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
env["SSL_CERT_FILE"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

# For Go-based tools
env["SSL_CERT_DIR"] = "/etc/pki/tls/certs"

# For curl
env["CURL_CA_BUNDLE"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
```

The `update-ca-trust` command adds the CA to the system bundle, so `SSL_CERT_FILE` and `CURL_CA_BUNDLE` point to the updated system bundle. `NODE_EXTRA_CA_CERTS` points directly to the CA cert file (Node.js appends it to its built-in roots).

**Timing:** The CA cert copy must happen after the proxy container is running (CA is generated at startup) and before the agent container makes any HTTPS requests. In the current flow, this fits between `self._proxy.start_proxy(session_name)` and the agent container start in `create_session()`.

**OpenShift:** For the OpenShift backend, the CA cert can be extracted from the proxy pod and injected into the agent pod via `oc cp`, or stored in a ConfigMap/Secret that both pods mount. Alternatively, use a shared emptyDir volume between the proxy and agent containers in the same pod. The NetworkPolicy already restricts agent egress to the proxy.

### 4. gcloud ADC stub file

Instead of mounting the real ADC JSON into the agent container, create and inject a stub:

```json
{
  "type": "authorized_user",
  "client_id": "paude-proxy-managed",
  "client_secret": "paude-proxy-managed",
  "refresh_token": "paude-proxy-managed"
}
```

Write this to the agent container at the same path where the real ADC would go (`~/.config/gcloud/application_default_credentials.json`, defined as `GCP_ADC_TARGET` in `constants.py`).

Set `GOOGLE_APPLICATION_CREDENTIALS` in the agent container pointing to this stub file (same path as today).

The real ADC file must be mounted/injected into the **proxy** container instead, with `GOOGLE_APPLICATION_CREDENTIALS` pointing to it there.

**How it works:** The agent's Google Auth library reads the stub, POSTs to `oauth2.googleapis.com/token` to exchange the dummy refresh_token. The proxy intercepts this request and returns a dummy access token. The agent uses this dummy token in API calls. The proxy's `GCloudInjector` replaces the dummy Bearer header with a real token (from the proxy's own ADC) before forwarding to Google. The agent never sees any real credential.

### 5. Drop squid-specific configuration

- **Remove `format_domains_as_squid_acls()` call** from `proxy_runner.py:_build_env_args()`. paude-proxy uses `ALLOWED_DOMAINS` (comma-separated), which is already passed. The `ALLOWED_DOMAIN_ACLS` env var is no longer needed.
- **Remove `remove_wildcard_covered()`** from domain expansion. This function exists because squid treats `.example.com` as matching both `example.com` and `*.example.com`, making both a fatal config error. paude-proxy handles both forms independently — `.example.com` is a suffix match, `example.com` is exact. Having both is harmless.
- **Keep `SQUID_DNS`** — paude-proxy's entrypoint reads this env var for custom DNS. The name is legacy but functional. Can optionally be renamed later.
- **Keep `ALLOWED_OTEL_PORTS`** — paude-proxy uses this for port filtering (same format: comma-separated port numbers).

### 6. Blocked domains CLI

The `paude blocked-domains` command reads `/tmp/squid-blocked.log` via `cat` inside the proxy container. paude-proxy writes to the same path in a compatible format. **No changes needed** — `proxy_log.py:parse_blocked_log()` will parse paude-proxy's output correctly.

The `SQUID_BLOCKED_LOG_PATH` constant in `shared.py` can optionally be renamed, but the default path matches.

### 7. Domain update (recreate proxy)

`PodmanProxyManager.update_domains()` stops and recreates the proxy container with new domain configuration. This works as-is with paude-proxy. Since `/data/ca` is mounted as a volume, the CA cert persists across proxy recreations — no need to re-copy the cert to the agent container after domain updates.

## Environment variable mapping

### Proxy container

Mount `/data/ca` as a named volume so the CA persists across restarts.

| Variable | Value | Notes |
|---|---|---|
| `ALLOWED_DOMAINS` | Comma-separated domain list | Already passed today |
| `ALLOWED_OTEL_PORTS` | Comma-separated port numbers | Already passed today |
| `SQUID_DNS` | Custom upstream DNS server | Already passed today |
| `ANTHROPIC_API_KEY` | Real API key from host | **NEW** — move from agent |
| `OPENAI_API_KEY` | Real API key from host | **NEW** — move from agent |
| `CURSOR_API_KEY` | Real API key from host | **NEW** — move from agent |
| `GH_TOKEN` | Real GitHub PAT from host | **NEW** — move from agent |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to real ADC JSON | **NEW** — mount file + set path |
| `PAUDE_PROXY_VERBOSE` | `1` for debug logging | Optional |

### Agent container

| Variable | Value | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | `paude-proxy-managed` | **CHANGED** — was real key |
| `OPENAI_API_KEY` | `paude-proxy-managed` | **CHANGED** — was real key |
| `CURSOR_API_KEY` | `paude-proxy-managed` | **CHANGED** — was real key |
| `GH_TOKEN` | `paude-proxy-managed` | **CHANGED** — was real key |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to stub ADC JSON | **CHANGED** — stub, not real |
| `NODE_EXTRA_CA_CERTS` | `/etc/pki/ca-trust/source/anchors/paude-proxy-ca.crt` | **NEW** |
| `REQUESTS_CA_BUNDLE` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | **NEW** |
| `SSL_CERT_FILE` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | **NEW** |
| `HTTP_PROXY` | `http://<proxy-ip>:3128` | Unchanged |
| `HTTPS_PROXY` | `http://<proxy-ip>:3128` | Unchanged |

## Behavioral differences from squid

### Certificate pinning

Some tools pin TLS certificates and will reject the proxy's MITM certificates. If this occurs, those tools will need to be configured to trust the proxy CA or disable pinning. This is most likely to affect:
- Git (if configured with `http.sslCAInfo` or `http.sslVerify`)
- Package managers with pinned certificates

The CA trust env vars listed above should handle most cases. Git respects the system CA bundle after `update-ca-trust`.

### CONNECT rejection

Squid returns HTTP 403 for blocked CONNECT requests. goproxy rejects the TCP connection. Most HTTP clients handle both gracefully, but error messages will differ. If agents parse proxy error responses, they may need updates.

### Port filtering

paude-proxy now enforces the same port restrictions as squid:
- HTTP requests: ports 80 and 443 only
- CONNECT (HTTPS): port 443 only
- Additional ports via `ALLOWED_OTEL_PORTS`

### Proxy identity headers

paude-proxy strips `Via` and `X-Forwarded-For` headers before forwarding, matching squid's `via off` / `forwarded_for delete` configuration.

## Rollout strategy

Consider a phased rollout:

1. **Phase 1: Build and publish paude-proxy image.** Add image to the registry alongside the squid image. Both available.

2. **Phase 2: Add paude-proxy support behind a flag.** Add a `--proxy-type=mitm` flag (or similar) to `paude create`. When set, use the paude-proxy image and the new credential flow. Default remains squid.

3. **Phase 3: Test with each agent type.** Verify Claude Code, Cursor, Gemini CLI, and OpenClaw all work through the MITM proxy. Key things to test:
   - Agent SDK initialization with dummy credentials
   - API calls succeed with injected credentials
   - gcloud ADC token flow works (Vertex AI / Gemini)
   - GitHub operations work (clone, push, PR creation)
   - Package installation works (pip, npm, go get)
   - Domain blocking still works
   - Blocked domains log is readable

4. **Phase 4: Make paude-proxy the default.** Flip the default, keep squid as fallback.

5. **Phase 5: Remove squid.** Drop squid image, `format_domains_as_squid_acls()`, `ALLOWED_DOMAIN_ACLS`, and `remove_wildcard_covered()`.

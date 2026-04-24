# Stateful OpenClaw Design

This repo has two operating modes:

- the deployed two-container stack
- the local verified Python browser gateway

## Two-Container Deployment

```text
browser
  |
  v
auth-proxy :8080
  |
  +--> /api/public/config
  +--> /api/public/challenge
  +--> /api/private/session/*
  +--> /openclaw/*
  +--> /aux-application/*
  |
  v
openclaw bootstrap 127.0.0.1:18788
  |
  v
openclaw gateway 127.0.0.1:18789
```

### Responsibilities

`auth-proxy`

- serves the unlock page at `/`
- publishes the owner challenge endpoints
- validates signed owner-auth requests
- forwards `bootstrap_env` to the OpenClaw bootstrap server
- issues the browser session cookie
- proxies HTTP and WebSocket traffic to OpenClaw
- forwards `/aux-application/*` to `127.0.0.1:3000` inside the enclave

`openclaw-runtime`

- starts a loopback bootstrap server first
- waits for bootstrap env from `auth-proxy`
- writes `~/.openclaw/openclaw.json`
- forces Anthropic-first defaults:
  - `anthropic/claude-sonnet-4-6`
  - fallback `anthropic/claude-opus-4-6`
- launches the real OpenClaw gateway only after bootstrap

### Browser Unlock Flow

```text
1. GET  /api/public/config
2. POST /api/public/challenge
3. browser signs exact request with owner private key
4. POST /api/private/session/login { bootstrap_env }
5. auth-proxy bootstraps OpenClaw
6. auth-proxy issues session cookie
7. browser redirects to /openclaw/
```

### Important Boundary

This browser flow currently verifies:

- server-configured `owner_key_id`
- local owner state
- challenge payload consistency
- exact request signature

It does **not** currently perform Tinfoil attestation verification in the browser.

## Local Verified Python Browser Gateway

This mode is for demos where the browser should not touch:

- the owner private key
- the upstream session cookie
- the raw remote Tinfoil connection

### Data Path

```text
browser
  |
  v
localhost python_client serve
  |
  +--> verifies Tinfoil attestation
  +--> pins upstream TLS key
  +--> loads owner state
  +--> signs owner-auth challenge
  +--> stores upstream session cookie locally
  |
  v
remote auth-proxy on Tinfoil
  |
  v
remote openclaw bootstrap
  |
  v
remote openclaw gateway
```

### What the Local Gateway Does

`VerifiedTinfoilTransport`

- fetches enclave attestation
- verifies enclave measurement against the expected release
- captures the attested TLS public key fingerprint
- creates a TLS-pinned HTTP client for the remote enclave

`AuthenticatedRemoteSession`

- loads remote public config
- checks the remote `owner_key_id`
- signs the owner-auth login locally
- keeps the upstream session cookie in Python
- retries upstream login on `401` when needed

`create_browser_gateway_app()`

- serves a local landing page at `/`
- exposes `/api/local/status`
- proxies browser HTTP and WebSocket requests onward
- injects the upstream cookie itself

### User Experience

```text
1. run python_client ... serve --mode tinfoil ...
2. local landing page opens on localhost
3. page shows:
   - attestation status
   - remote enclave URL
   - verification document
   - explanation of the trust path
4. user clicks "Open OpenClaw"
5. browser continues using localhost only
6. Python proxies all remote traffic through the verified connection
```

### Trust Model

In this mode:

- browser trusts the **local Python gateway**
- Python verifies the **remote enclave**
- all remote requests continue through Python

This means the correct statement is:

- “The local gateway verified the enclave and is proxying my browser traffic through that verified upstream connection.”

It is **not**:

- “The browser now independently has a verified direct connection to the enclave.”

If the browser leaves `localhost` and starts talking directly to the remote Tinfoil URL, this verified-local-gateway property is lost.

## Why `/aux-application/*` Exists

Tinfoil shim config is kept on a single public upstream port. Instead of exposing an extra public port for demo apps, `auth-proxy` path-routes:

```text
/aux-application/*  ->  http://127.0.0.1:3000/*
```

inside the enclave.

That lets OpenClaw create or serve a demo app internally while keeping the external deployment shape simple.

## Current Release

`tinfoil-config.yml` is pinned to:

- `ghcr.io/deevashwer/openclaw-auth-proxy:v0.0.8@sha256:c0910cc904d38f1c74ef12caa37ce0a6bfc8435dacd589b3fda40ee1dc0aba98`
- `ghcr.io/deevashwer/openclaw-runtime:v0.0.8@sha256:737356a7410c69e68c932d413b78ed282d18025ab3777a0f79492b633c15fb9d`

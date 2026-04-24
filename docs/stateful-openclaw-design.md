# Stateful OpenClaw Design

This repo now has two aligned operating modes:

- the deployed two-container stack
- the local Python verification center

## Two-Container Deployment

```text
browser
  |
  v
auth-proxy :8080
  |
  +--> /api/public/config
  +--> /api/public/init/*
  +--> /api/public/passkeys/authenticate/*
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
- starts generic and allows exactly one public initialization flow
- verifies WebAuthn/passkey registration and assertion server-side
- forwards `bootstrap_env` to the OpenClaw bootstrap server when upstream bootstrap is still needed
- issues the browser session cookie after successful passkey auth
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
fresh enclave:
1. GET  /api/public/config
2. POST /api/public/init/options
3. browser creates a passkey
4. POST /api/public/init/finish { credential, bootstrap_env }
5. auth-proxy bootstraps OpenClaw
6. auth-proxy stores the passkey and issues a session cookie
7. browser redirects to /openclaw/

claimed enclave:
1. GET  /api/public/config
2. POST /api/public/passkeys/authenticate/options
3. browser approves the saved passkey
4. POST /api/public/passkeys/authenticate/finish { credential, bootstrap_env? }
5. auth-proxy issues a session cookie
6. browser redirects to /openclaw/
```

### Important Boundary

In the active browser flow:

- the passkey is verified on the server side
- the browser-local vault stores `ANTHROPIC_API_KEY`
- the proxy stores only the passkey credential material and browser session state

The browser vault is currently IndexedDB under:

- database: `openclaw.auth-proxy.keystore.v2`
- object store: `vault`
- entries: `vaultKey`, `vaultCiphertext`, `vaultMeta`

## Local Python Verification Center

This mode exists to verify a remote Tinfoil deployment locally before the browser continues to the real enclave origin.

### Data Path

```text
browser
  |
  v
localhost python_client serve
  |
  +--> verifies Tinfoil attestation
  +--> pins upstream TLS key
  +--> fetches remote public config
  +--> renders local verification status
  |
  v
browser continues to remote auth-proxy origin
  |
  +--> passkey approval
  +--> browser-local secret vault
  +--> remote browser session cookie
  |
  v
remote openclaw gateway
```

### What the Local Verification Center Does

`VerifiedTinfoilTransport`

- fetches enclave attestation
- verifies enclave measurement against the expected release
- captures the attested TLS public key fingerprint
- creates a TLS-pinned HTTP client for the remote enclave

`VerifiedLaunchSession`

- loads remote public config
- records whether initialization is still available
- exposes the remote unlock URL

`create_browser_gateway_app()`

- serves a local landing page at `/`
- exposes `/api/local/status`
- redirects `/launch` to the real remote unlock page

### User Experience

```text
1. run python_client ... serve --mode tinfoil ...
2. local verification center opens on localhost
3. page shows:
   - attestation status
   - remote enclave URL
   - passkey claim state
   - verification document
4. user clicks "Open Remote Unlock Page"
5. browser moves to the real remote enclave origin
6. passkey auth and secret storage happen there
```

### Trust Model

In this mode:

- Python verifies the remote enclave
- the browser still authenticates directly with the remote enclave origin
- Python is not the authenticated proxy anymore

So the correct statement is:

- "Python verified the enclave locally, and then the browser continued to the real enclave origin for passkey auth."

It is not:

- "Python authenticated to the enclave on the browser's behalf."

## Why `/aux-application/*` Exists

Tinfoil shim config is kept on a single public upstream port. Instead of exposing an extra public port for demo apps, `auth-proxy` path-routes:

```text
/aux-application/*  ->  http://127.0.0.1:3000/*
```

inside the enclave.

That lets OpenClaw create or serve a demo app internally while keeping the external deployment shape simple.

# OpenClaw Auth Proxy

Minimal setup:

- `openclaw`: custom runtime image with a loopback bootstrap server
- `auth-proxy`: only public ingress
- `python_client`: local owner-auth, verification, and browser-gateway tooling

Architecture and trust-path diagrams live in [`docs/stateful-openclaw-design.md`](docs/stateful-openclaw-design.md).

## Files

- [`docker-compose.yml`](docker-compose.yml): local two-container stack
- [`tinfoil-config.yml`](tinfoil-config.yml): Tinfoil deployment config
- [`openclaw-runtime/`](openclaw-runtime): custom OpenClaw wrapper image
- [`auth-proxy/`](auth-proxy): FastAPI proxy and browser unlock page
- [`python_client/`](python_client): local client for `bootstrap`, `verify`, `request`, `chat`, and `serve`

## Local Stack

Create owner state:

```bash
ANTHROPIC_API_KEY=your-key-here \
python3 python_client/owner_auth_chat.py bootstrap \
  --state-file /tmp/openclaw-owner-state.json \
  --force
```

Copy the printed `OWNER_PUBLIC_KEY_JWK=...` into `.env`, then start:

```bash
docker compose up --build
```

Use:

- browser unlock flow: `http://127.0.0.1:8080/`
- direct verify:

```bash
python3 python_client/owner_auth_chat.py verify \
  --mode local \
  --state-file /tmp/openclaw-owner-state.json \
  --base-url http://127.0.0.1:8080
```

- direct signed request:

```bash
python3 python_client/owner_auth_chat.py request \
  --mode local \
  --state-file /tmp/openclaw-owner-state.json \
  --base-url http://127.0.0.1:8080 \
  GET /openclaw/__openclaw/control-ui-config.json
```

## Verified Local Browser Gateway

Use this when you want local Python to:

- verify Tinfoil attestation
- pin the upstream TLS key
- hold the owner state locally
- keep the remote session cookie out of the browser
- serve a local landing page before opening OpenClaw

Example against the deployed smoke test:

```bash
python3 python_client/owner_auth_chat.py serve \
  --mode tinfoil \
  --state-file /tmp/openclaw-owner-state.json \
  --enclave openclaw-smoke-test.devesh-org.containers.tinfoil.dev \
  --repo deevashwer/container-config \
  --release-tag v0.0.8 \
  --host 127.0.0.1 \
  --port 8090 \
  --open-browser
```

What happens:

1. Python verifies the remote enclave and release measurement.
2. Python signs the owner-auth login with the local state.
3. Python keeps the upstream session cookie locally.
4. Browser opens `http://127.0.0.1:8090/`.
5. Browser traffic continues through the local gateway to the verified remote enclave.

Important:

- keep using the `localhost` URL for the verified demo
- do not switch the browser over to the remote Tinfoil URL after verification

Useful local endpoints while `serve` is running:

- landing page: `http://127.0.0.1:8090/`
- raw local status: `http://127.0.0.1:8090/api/local/status`
- proxied OpenClaw UI: `http://127.0.0.1:8090/openclaw/`

## Aux Application Demo

An auxiliary HTTP app listening inside the enclave on `127.0.0.1:3000` is exposed through:

```text
/aux-application/*
```

That path is forwarded by `auth-proxy`; no second public shim port is required.

## Releases

Current published release used by `tinfoil-config.yml`:

- `ghcr.io/deevashwer/openclaw-auth-proxy:v0.0.8@sha256:c0910cc904d38f1c74ef12caa37ce0a6bfc8435dacd589b3fda40ee1dc0aba98`
- `ghcr.io/deevashwer/openclaw-runtime:v0.0.8@sha256:737356a7410c69e68c932d413b78ed282d18025ab3777a0f79492b633c15fb9d`

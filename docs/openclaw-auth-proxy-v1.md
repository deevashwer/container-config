# OpenClaw Auth Proxy V1

This is the reduced model:

- `auth-proxy/` is the only public ingress
- it exposes only the auth bootstrap endpoints
- every other request is authenticated, then forwarded unchanged to OpenClaw
- OpenClaw runs on private loopback behind the proxy

## Proxy Surface

Public:

- `GET /healthz`
- `GET /api/public/config`
- `POST /api/public/challenge`

Authenticated and forwarded:

- every other path

The proxy does not implement app-specific endpoints anymore. It just:

1. issues a one-time challenge for `(method, path, body_sha256)`
2. verifies the owner signature
3. strips the auth headers
4. forwards the original request upstream
5. returns the upstream response as-is

## Local Composition

`docker-compose.yml` uses a shared network namespace so the proxy reaches OpenClaw on loopback:

- OpenClaw listens on `127.0.0.1:18789`
- the proxy points `UPSTREAM_BASE_URL` at `http://127.0.0.1:18789`
- the owner public key is injected through `OWNER_PUBLIC_KEY_JWK`

OpenClaw is configured with `gateway.auth.mode: "none"` because the proxy is the only intended ingress.

## Files

- `auth-proxy/app/main.py`
- `auth-proxy/app/security.py`
- `auth-proxy/app/settings.py`
- `docker-compose.yml`
- `tinfoil-config.auth-proxy.example.yml`

## Verified Locally

- rebuilt `openclaw-auth-proxy:verify`
- embedded test suite passed
- validated authenticated forwarding with the local Python client

## Next Step

Keep this layer unchanged and wire the client to real passkey signing later. The proxy should stay generic.

# Minimal OpenClaw Stack

This repo is intentionally reduced to the current working shape:

- `openclaw` runs the official image on loopback only
- `auth-proxy` is the only public ingress
- `python_client` remains available for `bootstrap`, `verify`, `request`, `chat`, and `serve`

## Runtime Model

```text
browser or python_client
          |
          v
    auth-proxy :8080
          |
          v
 openclaw 127.0.0.1:18789
```

## OpenClaw

OpenClaw is configured at container start with:

- `gateway.mode = "local"`
- `gateway.bind = "loopback"`
- `gateway.auth.mode = "none"`
- `gateway.controlUi.basePath = "/openclaw"`

Because OpenClaw only listens on loopback behind the proxy, its Control UI origin checks are relaxed for now.

## Auth Proxy

The auth proxy owns:

- the browser unlock page at `/`
- `GET /api/public/config`
- `POST /api/public/challenge`
- session creation and logout under `/api/private/session*`
- authenticated HTTP and WebSocket forwarding for everything else

The browser flow is:

1. load owner state JSON
2. request a one-time challenge
3. sign it locally
4. mint the browser session cookie
5. redirect to `/openclaw/`

## Python Client

The Python client stays in the repo because it is the direct verification and request surface:

- `bootstrap` creates the owner state file
- `verify` checks server config and Tinfoil attestation details when needed
- `request` and `chat` hit proxy endpoints directly
- `serve` runs a localhost browser gateway that holds the remote session in Python

See [`python-owner-chat-v1.md`](python-owner-chat-v1.md) for command examples.

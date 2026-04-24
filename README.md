# OpenClaw Auth Proxy

This repo is now the minimal two-container stack:

- `openclaw`: the public OpenClaw image, bound to loopback only
- `auth-proxy`: the only public ingress, responsible for owner challenge-response and forwarding the browser into the real OpenClaw UI at `/openclaw/`

Anything outside that shape has been removed on purpose. The current task list lives in [`TODO.md`](TODO.md).

## Layout

- [`docker-compose.yml`](docker-compose.yml): local bring-up from the checked-in `auth-proxy/` source
- [`tinfoil-config.yml`](tinfoil-config.yml): Tinfoil deployment shape
- [`auth-proxy/`](auth-proxy): FastAPI proxy, browser unlock page, and tests
- [`python_client/`](python_client): owner-auth client for `bootstrap`, `verify`, `request`, `chat`, and `serve`

## Local Bring-Up

1. Generate an owner keypair and browser-importable state file:

   ```bash
   python3 python_client/owner_auth_chat.py bootstrap \
     --state-file /tmp/openclaw-owner-state.json \
     --force
   ```

2. Copy the printed `OWNER_PUBLIC_KEY_JWK=...` value into `.env`.

3. Start the local stack:

   ```bash
   docker compose up --build
   ```

4. Open `http://127.0.0.1:8080/`, load `/tmp/openclaw-owner-state.json`, and the page will create the proxy session and redirect you to `/openclaw/`.

5. Verify or hit endpoints directly from Python when needed:

   ```bash
   python3 python_client/owner_auth_chat.py verify \
     --mode local \
     --state-file /tmp/openclaw-owner-state.json \
     --base-url http://127.0.0.1:8080
   ```

   ```bash
   python3 python_client/owner_auth_chat.py request \
     --mode local \
     --state-file /tmp/openclaw-owner-state.json \
     --base-url http://127.0.0.1:8080 \
     GET /openclaw/__openclaw/control-ui-config.json
   ```

## Runtime Shape

- OpenClaw runs with `gateway.bind="loopback"` and `gateway.auth.mode="none"`.
- The OpenClaw Control UI stays under `/openclaw`.
- Origin checks are relaxed inside OpenClaw because it only listens on loopback behind the proxy.
- The auth proxy exposes only:
  - `/`
  - `/assets/*`
  - `/favicon.svg`
  - `/healthz`
  - `/api/public/*`
  - authenticated forwarding for everything else, including WebSockets

## Tinfoil Note

`docker-compose.yml` builds `auth-proxy` from the local source. `tinfoil-config.yml` still expects a published `auth-proxy` image tag. When you change `auth-proxy/`, publish a matching image and update the tag/digest in `tinfoil-config.yml`.

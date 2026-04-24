# OpenClaw Auth Proxy

This repo is now the minimal two-container stack:

- `openclaw`: a custom runtime image built on top of the public OpenClaw image
- `auth-proxy`: the only public ingress, responsible for owner challenge-response and forwarding the browser into the real OpenClaw UI at `/openclaw/`

Anything outside that shape has been removed on purpose. The current task list lives in [`TODO.md`](TODO.md).

## Layout

- [`docker-compose.yml`](docker-compose.yml): local bring-up from the checked-in `auth-proxy/` source
- [`openclaw-runtime/`](openclaw-runtime): custom OpenClaw wrapper image with a localhost bootstrap server
- [`tinfoil-config.yml`](tinfoil-config.yml): Tinfoil deployment shape
- [`auth-proxy/`](auth-proxy): FastAPI proxy, browser unlock page, and tests
- [`python_client/`](python_client): owner-auth client for `bootstrap`, `verify`, `request`, `chat`, and `serve`

## Local Bring-Up

1. Generate an owner keypair and browser-importable state file. If `ANTHROPIC_API_KEY` is present in your shell, `bootstrap` stores it under `bootstrap_env` in the state JSON:

   ```bash
   ANTHROPIC_API_KEY=your-key-here \
   python3 python_client/owner_auth_chat.py bootstrap \
     --state-file /tmp/openclaw-owner-state.json \
     --force
   ```

2. Copy the printed `OWNER_PUBLIC_KEY_JWK=...` value into `.env`.
3. Start the local stack:

   ```bash
   docker compose up --build
   ```

4. Open `http://127.0.0.1:8080/`, load `/tmp/openclaw-owner-state.json`, and the page will send the state’s `bootstrap_env` to `auth-proxy` during signed session init. `auth-proxy` forwards that env to the loopback-only OpenClaw bootstrap server, which then launches OpenClaw and redirects you to `/openclaw/`.

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

- The custom `openclaw` runtime container starts a loopback-only bootstrap server first.
- `auth-proxy` receives `bootstrap_env` from the signed owner-init request and forwards it to that bootstrap server before it issues the browser session.
- The bootstrap server then launches OpenClaw with `gateway.bind="loopback"` and `gateway.auth.mode="none"`.
- During bootstrap it also writes Anthropic-first agent defaults, so the initial session uses `anthropic/claude-sonnet-4-6` with an Anthropic-only fallback instead of stale Bedrock/OpenAI overrides.
- Cold starts can take a while on this image, so the proxy/bootstrap handshake now allows up to 90 seconds for OpenClaw to become healthy.
- The OpenClaw Control UI stays under `/openclaw`.
- A demo HTTP service running inside the enclave on `127.0.0.1:3000` can be reached through the proxy at `/aux-application/*`.
- Origin checks are relaxed inside OpenClaw because it only listens on loopback behind the proxy.
- The auth proxy exposes only:
  - `/`
  - `/assets/*`
  - `/favicon.svg`
  - `/healthz`
  - `/api/public/*`
  - authenticated forwarding for everything else, including WebSockets

## Tinfoil Note

`docker-compose.yml` now builds both `auth-proxy` and the custom `openclaw-runtime` image from local source. `tinfoil-config.yml` still expects published image tags, so a remote rollout now needs a published `auth-proxy` image and a published custom OpenClaw runtime image with the same bootstrap behavior.

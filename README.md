# OpenClaw On Tinfoil

This repo is now a thin Tinfoil deployment wrapper around the official OpenClaw GHCR image.

## What Is Configured

- `tinfoil-config.yml` points at `ghcr.io/openclaw/openclaw:2026.4.15-slim`
- the image is pinned to the published amd64 digest
- startup writes a minimal `openclaw.json` that forces:
  - `gateway.mode=local`
  - `gateway.bind=lan`
  - `gateway.auth.mode=token`
  - a fresh random bootstrap token on every container start
  - `gateway.controlUi.basePath=/openclaw`
  - `gateway.controlUi.embedSandbox=strict`
  - `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true`
  - `gateway.controlUi.dangerouslyDisableDeviceAuth=true`
- startup prints the generated bootstrap token to container logs as `bootstrap_token=...`
- `.github/workflows/tinfoil-build.yml` measures the image and publishes a GitHub release when you push a `v*` tag
- the Tinfoil shim exposes only the Control UI shell, static assets, and the `/openclaw` WebSocket mount

## Release Flow

1. Commit any config changes.
2. Push a tag such as `v0.0.1`.
3. Wait for **Build and Attest** in GitHub Actions to finish.
4. The workflow publishes the matching GitHub release for that tag.
5. In the Tinfoil dashboard, deploy that repo/tag.

## Manual Steps You Still Need To Do

1. Wait for the `v*` tag workflow to finish in GitHub Actions.
2. In the Tinfoil dashboard, deploy this repo/tag from **Containers**. No Tinfoil secrets are required for this smoke test.
3. After the container starts, open the deployment logs in Tinfoil and copy the `bootstrap_token=...` value.
4. Open the public deployment URL that Tinfoil shows you and append `/openclaw/#token=<bootstrap_token>`.
5. Use `/openclaw/` as the entry path for this first test; the shim intentionally does not expose deep-linked tab routes directly.
6. Optionally connect the repo with the Tinfoil GitHub App so release promotion and auto-update work cleanly.

## Important Limitations

- This is a quick bring-up, not a durable OpenClaw home. OpenClaw stores config, auth profiles, and session state under `/home/node/.openclaw`, and this Tinfoil setup does not provide persistent storage for that path.
- Tinfoil now exposes only the dashboard shell, its static assets, and the `/openclaw` WebSocket mount. OpenClaw helper routes such as bootstrap JSON, avatar, assistant media, canvas, health probes, and other gateway endpoints are not reachable from the public Tinfoil URL.
- The static Control UI shell still loads publicly at `/openclaw/`, because the browser must load the app before it can present or use the token. The admin session still depends on the generated gateway token over WebSocket.
- The bootstrap token is intentionally printed to container logs so you can complete the first login without Tinfoil secret injection. Treat that token as temporary and fetch a new one after any container restart.
- This smoke-test config intentionally uses both `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true` and `gateway.controlUi.dangerouslyDisableDeviceAuth=true`. They are break-glass shortcuts for first deploy, not a hardened long-term setup.
- Bonjour is disabled because there is an open upstream headless-Docker issue around mDNS advertisement loops. That should be fine for Tinfoil because mDNS discovery is not useful there.

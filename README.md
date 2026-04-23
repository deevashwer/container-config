# OpenClaw On Tinfoil

This repo is now a thin Tinfoil deployment wrapper around the official OpenClaw GHCR image.

## What Is Configured

- `tinfoil-config.yml` points at `ghcr.io/openclaw/openclaw:2026.4.15-slim`
- the image is pinned to the published amd64 digest
- startup writes a minimal `openclaw.json` that forces:
  - `gateway.mode=local`
  - `gateway.bind=lan`
  - `gateway.auth.mode=token`
  - `gateway.controlUi.basePath=/openclaw`
  - `gateway.controlUi.embedSandbox=strict`
  - `gateway.controlUi.allowedOrigins=[<exact https origin>]`
  - `gateway.controlUi.dangerouslyDisableDeviceAuth=true`
- startup fails closed unless both `OPENCLAW_GATEWAY_TOKEN` and `OPENCLAW_CONTROL_UI_ORIGIN` are present
- `OPENCLAW_GATEWAY_TOKEN` and `OPENCLAW_CONTROL_UI_ORIGIN` are expected from Tinfoil's encrypted secret store
- `.github/workflows/tinfoil-build.yml` is still the stock Tinfoil measurement workflow and runs when you push a `v*` tag
- the Tinfoil shim exposes only the Control UI shell, static assets, tab routes, and the `/openclaw` WebSocket mount

## Release Flow

1. Commit any config changes.
2. Push a tag such as `v0.0.1`.
3. Wait for **Build and Attest** in GitHub Actions.
4. In the Tinfoil dashboard, deploy that repo/tag.

## Manual Steps You Still Need To Do

1. Pick the Tinfoil deployment name you will use, then compute the final container origin as `https://<name>.<org>.containers.tinfoil.dev`.
2. In the Tinfoil dashboard, add a secret named `OPENCLAW_GATEWAY_TOKEN` with a long random value.
3. Add a second secret named `OPENCLAW_CONTROL_UI_ORIGIN` with that exact `https://<name>.<org>.containers.tinfoil.dev` origin.
4. Deploy this repo/tag from **Containers** in the Tinfoil dashboard.
5. Open `https://<name>.<org>.containers.tinfoil.dev/openclaw/#token=<OPENCLAW_GATEWAY_TOKEN>` for direct token bootstrap.
6. If you do not want the token in the URL, open `/openclaw/` and paste the same token into the UI when prompted.
7. Optionally connect the repo with the Tinfoil GitHub App so release promotion and auto-update work cleanly.

## Important Limitations

- This is a quick bring-up, not a durable OpenClaw home. OpenClaw stores config, auth profiles, and session state under `/home/node/.openclaw`, and this Tinfoil setup does not provide persistent storage for that path.
- Tinfoil now exposes only the dashboard shell, its static assets, the known SPA tab routes, and the `/openclaw` WebSocket mount. OpenClaw's helper routes such as bootstrap JSON, avatar, assistant media, canvas, health probes, and any other gateway endpoints are not reachable from the public Tinfoil URL.
- The static Control UI shell still loads publicly at `/openclaw/`, because the browser must load the app before it can present or use the token. The admin session itself still depends on the gateway token over WebSocket.
- OpenClaw normally requires one-time pairing approval for a new browser. To make first-boot public token access work on Tinfoil, this setup intentionally uses `gateway.controlUi.dangerouslyDisableDeviceAuth=true`. That is the main remaining security compromise. If you later want the stricter paired-device model, we need a different approval flow than direct public token login.
- Bonjour is disabled because there is an open upstream headless-Docker issue around mDNS advertisement loops. That should be fine for Tinfoil because mDNS discovery is not useful there.

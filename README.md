# OpenClaw On Tinfoil

This repo is now a thin Tinfoil deployment wrapper around the official OpenClaw GHCR image.

## What Is Configured

- `tinfoil-config.yml` points at `ghcr.io/openclaw/openclaw:2026.4.15-slim`
- the image is pinned to the published amd64 digest
- startup writes a minimal `openclaw.json` that forces:
  - `gateway.mode=local`
  - `gateway.bind=lan`
  - token auth
  - `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true`
- `OPENCLAW_GATEWAY_TOKEN` is expected from Tinfoil's encrypted secret store
- `.github/workflows/tinfoil-build.yml` is still the stock Tinfoil measurement workflow and runs when you push a `v*` tag

## Release Flow

1. Commit any config changes.
2. Push a tag such as `v0.0.1`.
3. Wait for **Build and Attest** in GitHub Actions.
4. In the Tinfoil dashboard, deploy that repo/tag.

## Manual Steps You Still Need To Do

1. In the Tinfoil dashboard, add a secret named `OPENCLAW_GATEWAY_TOKEN` with a long random value.
2. Deploy this repo/tag from **Containers** in the Tinfoil dashboard.
3. Open the deployed Tinfoil URL in your browser.
4. In the OpenClaw Control UI, paste the same gateway token into Settings when prompted.
5. Optionally connect the repo with the Tinfoil GitHub App so release promotion and auto-update work cleanly.

## Important Limitations

- This is a quick bring-up, not a durable OpenClaw home. OpenClaw stores config, auth profiles, and session state under `/home/node/.openclaw`, and this Tinfoil setup does not provide persistent storage for that path.
- The current config uses `dangerouslyAllowHostHeaderOriginFallback` so we do not need to know the final Tinfoil URL ahead of time. Once you know the exact deployed URL, we should replace that with an explicit `gateway.controlUi.allowedOrigins` allowlist.
- Bonjour is disabled because there is an open upstream headless-Docker issue around mDNS advertisement loops. That should be fine for Tinfoil because mDNS discovery is not useful there.

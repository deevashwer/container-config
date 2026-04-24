# OpenClaw Auth Proxy

Minimal setup:

- `openclaw`: custom runtime image with a loopback bootstrap server
- `auth-proxy`: public ingress plus one-time enclave initialization and server-side passkey verification
- `python_client`: local verifier/launcher for the remote passkey flow

## Files

- [`docker-compose.yml`](docker-compose.yml): local two-container stack
- [`tinfoil-config.yml`](tinfoil-config.yml): Tinfoil deployment config
- [`openclaw-runtime/`](openclaw-runtime): custom OpenClaw wrapper image
- [`auth-proxy/`](auth-proxy): FastAPI proxy and browser unlock page
- [`python_client/`](python_client): local verification center and launcher for remote passkey auth
- [`docs/persistent-storage-sidecar-challenges.md`](docs/persistent-storage-sidecar-challenges.md): design constraints for a storage-managing sidecar

## Local Stack

Start the local stack:

```bash
docker compose up --build
```

Use the browser unlock flow at `http://localhost:8080/`.

First run:

1. Enter `ANTHROPIC_API_KEY` if the upstream bootstrap requires it.
2. Click `Initialize enclave and enter OpenClaw`.
3. Approve the passkey.

After that:

- the enclave is claimed and `/api/public/init/*` is no longer usable
- the server authenticates the browser with WebAuthn/passkeys
- the browser reuses the saved local bootstrap env after passkey approval
- later visits only need passkey approval unless you clear the local vault

Important local notes:

- use `localhost`, not `127.0.0.1`, for the browser passkey flow
- server-side passkeys are stored at `PASSKEY_STORE_PATH`
- the local bootstrap env vault is browser-local IndexedDB storage

Specifically:

- IndexedDB database: `openclaw.auth-proxy.keystore.v2`
- object store: `vault`
- entries: `vaultKey`, `vaultCiphertext`, `vaultMeta`

## Deployment Notes

- `auth-proxy` starts generic; the first successful passkey initialization claims it
- the auth proxy now persists passkey credentials at `PASSKEY_STORE_PATH`
- if you want passkeys to survive container recreation locally, keep the compose volume mounted
- the browser still owns `ANTHROPIC_API_KEY`; the proxy only receives it during initialization/login when upstream bootstrap is still needed

## Python Client

`python_client/owner_auth_chat.py` no longer performs direct authenticated requests. That old model depended on a local owner private key, which no longer exists.

What replaced it:

- `verify`: fetch `/api/public/config` and print attestation details when available
- `serve`: run a localhost verification center that links into the real remote unlock page
- `bootstrap`: print where secret state lives now and optionally purge the old `~/.config/openclaw-owner-chat/state.json`

The browser remains the owner of `ANTHROPIC_API_KEY` in this model. `python_client` does not persist that secret anymore.

Install the client dependencies first:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r python_client/requirements.txt
```

Local verification flow:

```bash
python3 python_client/owner_auth_chat.py verify \
  --mode local \
  --base-url http://127.0.0.1:8080
```

Local verified browser launch:

```bash
python3 python_client/owner_auth_chat.py serve \
  --mode local \
  --base-url http://127.0.0.1:8080 \
  --host 127.0.0.1 \
  --port 8090 \
  --open-browser
```

Remote Tinfoil verification against a release:

```bash
python3 python_client/owner_auth_chat.py verify \
  --mode tinfoil \
  --enclave YOUR-ENCLAVE-HOST.containers.tinfoil.dev \
  --repo deevashwer/container-config \
  --release-tag YOUR-RELEASE-TAG
```

Remote verified browser launch:

```bash
python3 python_client/owner_auth_chat.py serve \
  --mode tinfoil \
  --enclave YOUR-ENCLAVE-HOST.containers.tinfoil.dev \
  --repo deevashwer/container-config \
  --release-tag YOUR-RELEASE-TAG \
  --host 127.0.0.1 \
  --port 8090 \
  --open-browser
```

In `serve` mode:

- Python verifies the remote target first
- the local page shows the verification document and the current claim state
- `http://127.0.0.1:8090/launch` redirects the browser to the real remote unlock page
- passkey approval and browser-local secret storage still happen on the real enclave origin

If you want to pin a measurement directly instead of a release tag, use `--measurement-file` in `tinfoil` mode.

Current gap:

- the local Python verifier can carry its expected TLS and HPKE key fingerprints into the remote unlock page as a continuity hint
- the browser page does not yet cryptographically confirm that the later browser connection used those same attested keys

## Aux Application Demo

An auxiliary HTTP app listening inside the enclave on `127.0.0.1:3000` is exposed through:

```text
/aux-application/*
```

That path is forwarded by `auth-proxy`; no second public shim port is required.

## Verification Status

The browser unlock flow is now passkey-only on the server side. Verified locally:

- `python3 -m pytest auth-proxy/tests/test_app.py -q`
- local HTTP smoke for `GET /healthz`
- local HTTP smoke for `GET /api/public/config`
- local HTTP smoke for `POST /api/public/init/options`

Browser automation coverage for the passkey approval flow is still pending.

## Releases

Current published release used by `tinfoil-config.yml`:

- `ghcr.io/deevashwer/openclaw-auth-proxy:v0.0.8@sha256:c0910cc904d38f1c74ef12caa37ce0a6bfc8435dacd589b3fda40ee1dc0aba98`
- `ghcr.io/deevashwer/openclaw-runtime:v0.0.8@sha256:737356a7410c69e68c932d413b78ed282d18025ab3777a0f79492b633c15fb9d`

Tag push automation:

- pushing a `v*` tag now publishes both GHCR images automatically
- the workflow then renders a release-specific `tinfoil-config.yml` with the new image digests
- Tinfoil attestation artifacts are generated from that rendered config and uploaded to the GitHub release
- after a successful release, the workflow also updates the tracked `tinfoil-config.yml` and release refs in `README.md` on the default branch

# Python Owner Client V1

This client is intentionally generic.

- it stores one local owner key
- it can use plain local HTTP or a Tinfoil-verified HTTPS transport
- it performs the challenge-response flow automatically
- it sends normal application requests after that

It is not OpenClaw-specific beyond the example paths you call.

## Files

- `python_client/owner_auth_chat.py`
- `python_client/requirements.txt`

## Commands

- `bootstrap`
  - create or print the local owner key state
- `verify`
  - fetch `/api/public/config`
  - check the owner key matches
  - print the attestation verification document in Tinfoil mode
  - supports either `repo@latest`, `repo + release tag`, or a pinned measurement file
- `request`
  - send one authenticated request to any path
- `chat`
  - small interactive shell around `request`
- `serve`
  - run a localhost browser gateway
  - verify the remote target in Python first
  - mint and hold the remote proxy session in Python
  - proxy the real OpenClaw UI to the browser so the browser never needs the owner key

## Local Demo

1. Install the local dependencies:

   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   pip install -r python_client/requirements.txt
   ```

2. Bootstrap the owner key:

   ```bash
   python3 python_client/owner_auth_chat.py bootstrap
   ```

3. Put the printed `OWNER_PUBLIC_KEY_JWK=...` into `.env` or the proxy container env.

4. Start the proxy + OpenClaw composition.

5. Verify the auth surface:

   ```bash
   python3 python_client/owner_auth_chat.py verify \
     --mode local \
     --base-url http://127.0.0.1:8080
   ```

6. Send a normal forwarded app request:

   ```bash
   python3 python_client/owner_auth_chat.py request \
     --mode local \
     --base-url http://127.0.0.1:8080 \
     GET /openclaw/__openclaw/control-ui-config.json
   ```

7. Run the localhost browser gateway and open the real OpenClaw UI through it:

   ```bash
   python3 python_client/owner_auth_chat.py serve \
     --mode local \
     --base-url http://127.0.0.1:8080 \
     --host 127.0.0.1 \
     --port 8090
   ```

   Then open:

   ```text
   http://127.0.0.1:8090/
   ```

   The root path redirects straight to the proxied OpenClaw workspace. In this
   mode:

   - the browser never signs challenges
   - the browser never reads the owner state file
   - Python performs the owner-auth login and holds the remote session cookie
   - if `--mode tinfoil` is used, Python also performs attestation verification
     before the browser ever connects

## SDK Fit

The client now uses the Tinfoil Python SDK's lower-level verifier pieces directly in `--mode tinfoil`:

- attestation fetch and verification
- Sigstore bundle verification
- TLS certificate pinning

This keeps the client proxy-agnostic, but avoids one brittle SDK assumption for custom containers: the stock Python `SecureClient(repo=...)` path always verifies against `releases/latest`. For deployments where you want an exact target, the client supports:

- `--repo owner/repo`
  - verify against the repo's latest published release
- `--repo owner/repo --release-tag vX.Y.Z`
  - verify against one specific release tag
- `--measurement-file path/to/measurement.json`
  - verify against a pinned expected measurement

For your current deployment shape, the tag-pinned form is the safest:

```bash
conda run -n tinfoil python python_client/owner_auth_chat.py verify \
  --state-file /tmp/openclaw-owner-demo-state.json \
  --mode tinfoil \
  --enclave YOUR_TINFOIL_HOSTNAME \
  --repo deevashwer/container-config \
  --release-tag v0.0.6
```

If you later want to verify enclave A but route requests through proxy B, that would need a small SDK extension for separate verification and routing URLs.

The `serve` command uses exactly that same transport and verification stack.
The difference is only what sits on top:

- `request` and `chat` expose a terminal interface
- `serve` exposes a localhost browser-facing reverse proxy for the actual
  OpenClaw UI

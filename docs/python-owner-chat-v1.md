# Python Passkey Verifier and Launcher

The file is still named `owner_auth_chat.py`, but the client no longer uses an owner key.

Current behavior:

- it verifies local or remote auth-proxy public config
- it can verify a remote Tinfoil deployment against an expected release or pinned measurement
- it can run a localhost verification center that launches the real remote passkey flow
- it does not mint authenticated requests directly

## Files

- `python_client/owner_auth_chat.py`
- `python_client/local_browser_proxy.py`
- `python_client/requirements.txt`

## Commands

- `bootstrap`
  - print where secret state lives now
  - optionally delete the deprecated `~/.config/openclaw-owner-chat/state.json`
- `verify`
  - fetch `/api/public/config`
  - print the remote unlock URL
  - print the attestation verification document in Tinfoil mode
  - supports either `repo@latest`, `repo + release tag`, or a pinned measurement file
- `serve`
  - run a localhost verification center
  - verify the remote target in Python first
  - show the verification document and remote claim state
  - link to the real remote unlock page where the browser performs passkey auth

Removed commands:

- `request`
- `chat`

Those commands depended on a Python-held owner private key. They now exit with a clear error because passkey auth happens in the browser on the enclave origin.

## Local Demo

1. Install the local dependencies:

   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   pip install -r python_client/requirements.txt
   ```

2. Check where secrets live and purge the old Python state file if needed:

   ```bash
   python3 python_client/owner_auth_chat.py bootstrap --purge-legacy-state
   ```

3. Verify a local auth-proxy:

   ```bash
   python3 python_client/owner_auth_chat.py verify \
     --mode local \
     --base-url http://127.0.0.1:8080
   ```

4. Run the localhost verification center:

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

   In this mode:

   - the local page shows verification state
   - the local page links to the real unlock page
   - passkey approval happens on the real auth-proxy origin
   - `ANTHROPIC_API_KEY` remains browser-local, not Python-local

## SDK Fit

The client still uses the Tinfoil Python SDK's verifier pieces directly in `--mode tinfoil`:

- attestation fetch and verification
- Sigstore bundle verification
- TLS certificate pinning

This keeps the verification path reusable while aligning the authenticated browser flow with the passkey-only auth-proxy.

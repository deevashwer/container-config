# Python Owner Client V1

This client is intentionally generic.

- it stores one local owner key
- it can use plain local HTTP or the Tinfoil Python SDK transport
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
- `request`
  - send one authenticated request to any path
- `chat`
  - small interactive shell around `request`

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

## SDK Fit

The client uses the low-level Tinfoil Python `SecureClient` in `--mode tinfoil`. No SDK changes are needed as long as the proxy is itself the attested public endpoint.

If you later want to verify enclave A but route requests through proxy B, that would need a small SDK extension for separate verification and routing URLs.

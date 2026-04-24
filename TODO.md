# TODO

## Now

- Keep the repo focused on two containers only: `openclaw` and `auth-proxy`.
- Keep OpenClaw on loopback with `auth.mode=none`.
- Keep `auth-proxy` as the only public ingress and require server-side WebAuthn before handing the browser into `/openclaw/`.
- Keep the browser flow simple: a fresh enclave is claimed once through the public init flow with `ANTHROPIC_API_KEY` plus passkey approval, and later runs only need passkey approval.
- Keep the browser-local bootstrap env separate from the server-side passkey store.

## Next

- Add a real browser automation pass for the passkey page once the in-app browser runtime or another supported browser harness is available.
- Decide whether `python_client/owner_auth_chat.py` should be renamed now that it is a passkey verifier/launcher rather than an owner-key client.
- Add attestation-verification UI on top of the Tinfoil SDK so the unlock page can surface the enclave proof directly.

## Later

- Support multiple passkeys per deployment instead of the current single-initializer claim flow.
- Harden session storage if the in-memory store stops being sufficient.
- Tighten the OpenClaw proxy surface if we learn specific paths can be blocked safely.

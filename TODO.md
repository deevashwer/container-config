# TODO

## Now

- Keep the repo focused on two containers only: `openclaw` and `auth-proxy`.
- Keep OpenClaw on loopback with `auth.mode=none`.
- Keep `auth-proxy` as the only public ingress and require owner challenge-response before handing the browser into `/openclaw/`.
- Keep the browser flow simple: load owner state JSON, create a session cookie, redirect to the real OpenClaw UI.
- Keep `python_client` as the verification and direct-request client surface.

## Next

- Deploy the published `auth-proxy` and custom `openclaw-runtime` images via `tinfoil-config.yml` and verify the browser bootstrap flow remotely.
- Decide whether the owner state file should stay as a local JSON import or move to a passkey-backed signing flow.
- Add a small smoke test that proves the browser unlock page can reach the OpenClaw Control UI over the proxy.

## Later

- Harden session storage if the in-memory store stops being sufficient.
- Tighten the OpenClaw proxy surface if we learn specific paths can be blocked safely.

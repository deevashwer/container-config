# Persistent Tinfoil Container Design

This document defines the recommended design for making a Tinfoil container persistent while keeping the application itself unaware of persistence, Merkle roots, and owner authentication.

It supersedes the earlier single-container direction in [`stateful-openclaw-design.md`](./stateful-openclaw-design.md) for the persistence/authentication workstream.

## Goals

- keep the application image mostly unchanged
- expose a normal writable directory to the application
- maintain a client-visible Merkle root for the committed application state
- fail closed on rollback, replay, stale-client, and bad-owner-auth cases
- let the client track the accepted state root across requests and restarts
- reuse Tinfoil’s existing attestation, shim, proxy, and passkey patterns where possible
- support a local `docker compose` loop for development

## Non-goals

- multi-writer coordination in V1
- background state mutation that bypasses the request proxy
- kernel-privileged storage features as a hard dependency
- perfect deduplication or snapshot efficiency in V1

## Research Summary

### What the kernel/storage options give us

- `dm-crypt` gives transparent block encryption and can use authenticated modes, but by itself it is not a Merkle-rooted state system.
- `dm-crypt` plus `dm-integrity` gives authenticated disk encryption, but integrity is per-sector and there is no global state root the client can track.
- `dm-verity` gives a Merkle-rooted block device, but it is read-only.
- `fs-verity` gives Merkle-rooted verification for individual files, but it is also read-only.
- Gramine encrypted files are the closest reference for an application-transparent encrypted filesystem with an internal Merkle tree, but Gramine explicitly does not protect against rollback/replay after file close.

### What this means for Tinfoil Containers

The Tinfoil container model clearly supports multiple containers, bind mounts, environment variables, secrets, and a single shim-exposed upstream port. It does not document privileged mode, loop devices, or device-mapper capabilities. For V1, we should assume we cannot rely on `dm-crypt`, `dm-verity`, loopback block devices, or kernel-mounted authenticated filesystems being available.

That pushes the practical design toward a userspace storage layer that:

- exposes a normal directory to the application
- computes and persists a Merkle-authenticated snapshot on request boundaries
- restores from a client-supplied root on cold start
- keeps the client as the source of truth for rollback protection

## Recommended V1 Architecture

Use three containers inside one Tinfoil enclave:

1. `state-guard`
2. `app`
3. `state-store`

Only `state-guard` is exposed through the Tinfoil shim.

### Component Roles

#### `app`

- runs the unmodified application image
- reads and writes a normal directory such as `/app-state`
- never sees Merkle roots, passkey assertions, or blob-store details

#### `state-store`

- owns restore and commit operations for `/app-state`
- chunks, encrypts, hashes, and uploads state objects to untrusted storage
- builds a deterministic Merkle tree over file contents and selected metadata
- tracks the currently restored `(generation, root)` in enclave memory

#### `state-guard`

- is the only public ingress
- verifies owner authentication for protected endpoints
- verifies the client’s expected `(generation, root)` before forwarding a request
- serializes state-mutating requests
- after the upstream response completes, asks `state-store` to commit and returns the new `(generation, root)` to the client

## High-Level Data Flow

```text
client
  |
  | 1. attestation + TLS to exposed Tinfoil container
  v
Tinfoil shim
  |
  v
state-guard
  |  \
  |   \-- verify owner assertion + expected root/generation
  |
  +----> app
  |
  \----> state-store commit/restore API
            |
            v
      untrusted blob store

response/trailer:
  current generation + current Merkle root
```

## Storage Design

### Storage Model

The application gets a normal writable directory, but committed state is represented as a manifest plus encrypted content blobs:

- file chunks are content-addressed
- file manifests describe chunk lists and file metadata
- directory manifests hash their children in sorted order
- the top manifest root is the client-visible state root

The committed head is:

```text
StateHead = {
  generation,
  root,
  parent_root,
  created_at,
  app_image_digest,
  manifest_version
}
```

### Deterministic Hashing Rules

Hash the logical state, not host-specific accidentals:

- include relative path
- include file type
- include mode bits
- include symlink target
- include file size
- include chunk hashes
- exclude atime
- exclude ctime
- exclude host inode numbers
- exclude container-specific absolute paths

Regular files, directories, and symlinks are supported in V1.

Sockets, FIFOs, device nodes, and mount points are rejected from the persistent subtree.

### Encryption

- each persisted blob is encrypted before leaving enclave storage
- blob encryption and manifest encryption use AEAD
- keys are derived from a state-encryption secret provisioned inside the enclave
- the Merkle root is computed over canonical plaintext semantics, not over ciphertext bytes

This keeps the root stable and comparable for the client, while still protecting the stored bytes.

### Restore

On cold start:

1. `state-guard` receives the first request with the client’s expected head
2. if no state is loaded yet, it asks `state-store` to `restore(root)`
3. `state-store` fetches the manifest by root, verifies that it hashes to the requested root, decrypts blobs, and recreates `/app-state`
4. `state-store` records the loaded `(generation, root)` in enclave memory

If the requested root cannot be restored exactly, the request fails immediately.

### Commit

For a state-mutating request:

1. `state-guard` checks the incoming `(generation, root)` against the current head
2. request is forwarded to `app`
3. after the upstream response finishes, `state-guard` calls `state-store.commit()`
4. `state-store` scans `/app-state`, uploads changed blobs, writes a new manifest, increments `generation`, and returns the new head
5. `state-guard` attaches the new head to the response

If commit fails after the app has mutated state, the enclave is marked tainted and must fail closed:

- return an error to the client
- reject follow-up requests
- restart from the last committed root

This is simpler and safer than trying to continue from a partially committed state.

## Why Not `dm-*` For V1

### `dm-crypt` + `dm-integrity`

Useful reference for authenticated encryption, but not enough for the client-visible root contract:

- no single Merkle root for the whole state
- likely requires block-device and device-mapper privileges we should not assume inside Tinfoil Containers

### `dm-verity`

Gives the right root shape but is read-only, so it cannot back an updatable app state directory.

### `fs-verity`

Also read-only, and per-file instead of giving us a writable application state volume.

### Gramine-style encrypted files

Strong design reference for app-transparent encrypted I/O and in-memory Merkle checking, but insufficient alone because rollback after close is explicitly out of scope there.

## Request Auth And Root Protocol

### Endpoint Classes

Default all proxied app endpoints to `owner-auth + root-check`.

Allow a small public list:

- `/.well-known/owner-challenge`
- `/health`
- optional static bootstrap assets

Everything else is protected unless explicitly opted out.

### Request Requirements

Protected requests carry:

- expected root
- expected generation
- challenge id
- owner assertion
- canonical request digest

Suggested headers:

```text
X-Tinfoil-State-Expected-Root
X-Tinfoil-State-Expected-Generation
X-Tinfoil-Owner-Challenge-Id
X-Tinfoil-Owner-Assertion
X-Tinfoil-Request-Digest
```

### Response Requirements

Non-streaming responses return:

```text
X-Tinfoil-State-Root
X-Tinfoil-State-Generation
```

Streaming responses return the state head as HTTP trailers after commit succeeds:

```text
Trailer: X-Tinfoil-State-Root, X-Tinfoil-State-Generation
```

### Challenge-Response

Use a passkey-backed challenge-response flow for owner-authenticated endpoints:

1. client requests `/.well-known/owner-challenge`
2. `state-guard` returns a short-lived nonce plus a canonical challenge payload
3. client signs the challenge with the owner passkey
4. `state-guard` verifies the assertion using the owner public key embedded in enclave env vars

The signed payload must bind:

- HTTP method
- path
- request digest
- expected root
- expected generation
- challenge expiry

This prevents replaying a signature onto a different request or a different state head.

### Enclave Environment Variables

`state-guard` needs:

- `OWNER_PASSKEY_PUBLIC_KEY`
- `OWNER_PASSKEY_CREDENTIAL_ID`
- `STATE_BACKEND_URL`
- `STATE_BACKEND_MODE`
- `STATE_BACKEND_SECRET` via Tinfoil secret
- `STATE_WORKDIR`

The public key can be a regular env var. Credentials for the backing store should be Tinfoil secrets.

### Provisioning Flow

The bootstrap path for the owner identity is:

1. register or select the owner passkey on the client
2. capture the credential ID and the corresponding public key during registration
3. store the client-side bundle locally and in passkey-backed encrypted backup
4. inject `OWNER_PASSKEY_PUBLIC_KEY` and `OWNER_PASSKEY_CREDENTIAL_ID` into the enclave deployment
5. allow `state-guard` to accept only assertions for that credential

If we cannot reliably export the public key from the exact passkey flow we want to reuse, generate a dedicated owner-auth credential at bootstrap and keep the PRF-based backup credential separate.

## Client-Side State

The client is the source of truth for rollback protection.

V1 client record:

```json
{
  "credentialId": "base64url...",
  "ownerPublicKey": "cose-or-jwk",
  "generation": 17,
  "root": "hex...",
  "authorizationMode": "validated",
  "bundleVersion": 3
}
```

### Reusing Tinfoil’s Existing Pattern

Tinfoil’s open-source web and iOS clients already have a good shape for this:

- a secure local primary store for client secrets/state
- a passkey-derived KEK for encrypted backup
- `sync_version` / `bundle_version` style conflict detection across devices

We should mirror that pattern for the container state head:

- web: keep the local head in browser storage next to the passkey bundle metadata, with encrypted app payloads remaining in IndexedDB or app-specific storage
- native: keep the owner secret material in Keychain/Keystore and lightweight sync metadata in local preferences
- backup: encrypt the state-head bundle with the same passkey-derived KEK and sync it the same way Tinfoil syncs encrypted key bundles

This lets another authorized device recover the latest accepted root without trusting the server.

## Docker Composition

### Tinfoil Deployment Shape

Use a multi-container `tinfoil-config.yml`:

- `state-guard` on the shim upstream port
- `app` reachable only on the enclave-internal network
- `state-store` reachable only on the enclave-internal network
- shared bind mounts for the live workdir and optional staging/cache directories

Suggested shared paths:

- `/mnt/ramdisk/live-state:/app-state`
- `/mnt/ramdisk/store-cache:/var/lib/state-store`

The app mounts `/app-state` at its persistent home, for example `/home/node/.openclaw`.

### Why `state-store` Is Separate From `state-guard`

- keeps storage logic reusable across applications
- keeps the reverse proxy smaller and easier to audit
- allows local testing of storage independently from auth/proxy logic

If needed, the first implementation can still keep both in one repo and split them into two binaries later.

## Local Development And Testing

### Local Topology

Add a `docker-compose.yml` with:

- `state-guard`
- `state-store`
- `app`
- optional `minio` or a simple local blob-store service

This should be the default development loop. Do not require a Tinfoil deployment just to test:

- root mismatch handling
- owner auth verification
- restore/commit behavior
- restart + recovery behavior

### Local Auth Modes

Support two modes:

1. browser/WebAuthn mode on `localhost` for real passkey flows
2. dev signing key mode for headless CI and CLI tests

The protocol should stay the same. Only the signer/verifier implementation changes.

### Test Matrix

Minimum local tests:

1. restore from empty state
2. restore from known root
3. commit after a mutating request
4. stale-root request rejected before hitting app
5. tampered blob fails on restore
6. invalid owner assertion rejected
7. streaming response returns root in trailer
8. restart from last committed head
9. cross-device conflict on state-head update
10. commit failure taints enclave and forces restart

## Implementation Plan

### Phase 1: Storage Engine

- define manifest format and canonical hashing rules
- implement deterministic tree walk
- implement chunk encryption and blob-store interface
- implement restore and commit APIs
- start with full-tree commit scans, not inode-level incremental tracking

### Phase 2: Guard Proxy

- implement public/protected route classification
- implement challenge issuance and assertion verification
- enforce `(expected_generation, expected_root)` preconditions
- add serialized commit flow and streaming trailer support
- fail closed on commit/restore/auth mismatch

### Phase 3: Client State Library

- define `StateHead` bundle format
- add local secure persistence
- add passkey-backed encrypted backup of the head
- add request signing helpers
- add stale-head recovery UX

### Phase 4: Deployment Wiring

- add multi-container `tinfoil-config.yml`
- inject owner public key and backend config through env/secrets
- mount the app state directory through shared enclave paths

### Phase 5: Local Harness

- add `docker-compose.yml`
- add an integration test app that mutates files predictably
- add end-to-end tests for restore/commit/auth/root mismatch

## Open Questions

- does the target application ever mutate persistent state outside request handling
- do we need to support background jobs or webhooks that change state without an interactive client present
- what is the production backing store: S3-compatible object storage, Tinfoil-managed API, or a custom service
- do we want the client to track only `root`, or `(generation, root)` as the canonical head
- is FUSE available in the enclave runtime later, so the same storage engine can expose a real mounted filesystem instead of a request-bound snapshot model

## Recommendation

Build V1 as a userspace Merkle snapshot store plus an outer guard proxy.

That gives us:

- application-agnostic persistence
- a client-visible, updatable Merkle root
- owner-authenticated request gating
- rollback protection anchored in the client
- a composition that fits Tinfoil’s documented multi-container and shim model

It is the safest path that matches both the security goal and the likely runtime constraints.

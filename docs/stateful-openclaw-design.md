# Stateful OpenClaw on Tinfoil

This is the bare-bones design for running OpenClaw in a Tinfoil container with:

- persistent state
- user-only access
- untrusted backing storage
- authenticated encryption
- rollback protection
- a user-controlled passkey as the root of authentication

Supporting note: [`storage-options.md`](storage-options.md)

## Design

Use one Tinfoil container.

Inside that container:

- run OpenClaw as the main service
- add a small bootstrap helper for browser/operator bootstrap
- add a storage layer that restores and commits `~/.openclaw`

The helper is only for bootstrap. OpenClaw still needs to expose the routes needed for channels, callbacks, and normal runtime traffic.

## Diagram

```text
                    Public Tinfoil URL
                     /                     \
                    /                       \
        browser bootstrap path         channel / webhook / runtime paths
                  |                               |
   verify enclave attestation                     |
                  |                               |
         authenticate with passkey                |
                  |                               |
  +--------------------------------------------------------------+
  |                  Single Tinfoil Container                     |
  |                                                              |
  |  Bootstrap Helper                                            |
  |  - first page / bootstrap                                    |
  |  - verifies passkey auth                                     |
  |  - establishes browser/operator session                      |
  |         |                                                    |
  |         v                                                    |
  |  OpenClaw                                                    |
  |  - gateway                                                   |
  |  - control UI                                                |
  |  - channels / callbacks / webhooks                           |
  |         |                                                    |
  |         v                                                    |
  |  Storage Layer                                               |
  |  - restore ~/.openclaw on boot/login                         |
  |  - commit encrypted state                                    |
  |  - verify freshness / rollback protection                    |
  +---------|----------------------------------------|-----------+
            |                                        |
            v                                        v
   Untrusted storage                         Freshness record
   encrypted blobs + metadata                counter or Merkle root
```

## What Needs To Happen

### 1. Persistent storage

We need one container with durable OpenClaw state.

OpenClaw should still read and write a normal local state directory, but that directory is restored from and committed to untrusted storage by the storage layer.

### 2. Bootstrap

We need a bootstrap path so only the authenticated user can access the enclave.

The flow is:

1. user connects
2. user verifies enclave attestation
3. user authenticates with their passkey
4. helper establishes browser/operator access to OpenClaw

This helper is only for browser/operator bootstrap. It should not be treated as the sole ingress for everything OpenClaw does.

### 2a. Channels and runtime traffic

OpenClaw itself still needs to handle non-browser traffic such as:

- channel integrations
- webhooks
- callbacks
- other runtime routes that are part of normal OpenClaw operation

So the design is not:

- "everything goes through the helper"

It is:

- "browser/operator bootstrap goes through the helper"
- "OpenClaw remains the main runtime service"

### 3. Untrusted storage

Persistent storage is untrusted by assumption.

So the storage layer must automatically provide:

- authenticated encryption for all persisted state
- integrity protection for metadata as well as file contents
- rollback protection

### 4. Rollback protection

Authenticated encryption alone is not enough, because the host can replay an older valid snapshot.

We need a freshness value, for example:

- a monotonic counter, or
- the latest Merkle tree root

The enclave should refuse to load state older than the user's latest accepted freshness value.

### 5. Passkey-rooted authentication

Everything should be authenticated with respect to a user-controlled passkey.

Target design:

- the passkey identifies the user
- the passkey binding is included in the enclave attestation report
- the user can verify they are talking to the right code and the right logical OpenClaw home

If direct inclusion in the attestation report is not available yet, treat it as a required extension point rather than falling back to a public bootstrap token.

## Storage Layer Requirements

The storage layer should look like a normal filesystem to OpenClaw, but internally it should:

- restore state into the container before use
- encrypt and authenticate state before writing it out
- maintain a freshness value for the latest committed state
- verify that freshness value before restoring

In other words, OpenClaw should not need to know about encryption, Merkle roots, or rollback checks directly.

## Recommendation

Keep the main design simple:

- one Tinfoil container
- one bootstrap helper for browser/operator access
- one OpenClaw runtime service
- one storage abstraction layer

Do not start with multiple containers unless process separation becomes necessary later.

## Related Note

- [`storage-options.md`](storage-options.md): short comparison of candidate storage approaches

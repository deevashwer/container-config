# Persistent Storage Sidecar Challenges

This note documents the challenges in a design where a dedicated
`persistent-storage` container manages a filesystem and tries to hand that
filesystem to `openclaw`.

In this note, "persistent" really means "state managed outside `openclaw`."
Whether the underlying bytes survive redeploys is a separate problem. The hard
part here is the filesystem handoff and control plane, not durability.

## Desired Workflow

The rough target design is:

1. `persistent-storage` starts first.
2. It prepares a filesystem, export, or mount.
3. `openclaw` later sees that storage at a normal local path.
4. `auth-proxy` and the bootstrap server may coordinate the sequence.

What makes this tricky is that Docker and the documented Tinfoil config are
good at static mounts declared before a container starts. They are not a clean
fit for "a sibling container creates a mount later and an already-running
container picks it up as a real filesystem mount."

## Main Challenges

### 1. Mount Ownership

Someone has to perform the actual mount operation.

- If `openclaw` mounts NFS or another network filesystem itself, the client
  container needs mount privileges and, for FUSE-based filesystems, extra
  device access.
- If `persistent-storage` performs the mount and tries to expose the result to
  `openclaw`, then the handoff depends on host-level mount behavior, bind
  propagation, or Docker-managed volumes rather than simple sibling networking.
- The documented `tinfoil-config.yml` surface does not expose Docker-style
  `cap_add`, `device`, or `privileged` controls, so designs that rely on those
  features should be treated as local-Docker-specific unless proven otherwise.

### 2. Static Mounts vs Dynamic Mounts

The clean container model is:

- define the mount
- start the container
- use the mount

The awkward model is:

- start container B first
- later create a new filesystem or host mount somewhere else
- expect running container B to pick it up automatically

That second model is exactly the behavior we would need for a true "storage
container mounts first, `openclaw` sees it later" workflow. It is not the
default operational model of Docker, and it is not documented as a Tinfoil
feature.

### 3. Tinfoil Supports Readiness Gating, Not Documented `depends_on`

Tinfoil documents:

- multiple containers inside one enclave
- container healthchecks
- boot waiting for a healthchecked container to become healthy

Tinfoil does not document:

- a Compose-style `depends_on`
- explicit sibling startup order
- runtime mutation of another container's mounts

That means there is a documented way to say "this container is not ready yet,"
but not a documented way to say "container A must finish mount setup and only
then may container B start with a new filesystem view."

### 4. Bind Propagation Is the Hidden Trap

Even if a host path is shared into both containers, a later mount created under
that host path is not automatically visible everywhere.

For that to work reliably, the relevant bind mount usually needs the right
propagation mode such as `shared`, `rshared`, `slave`, or `rslave`.

Problems:

- Docker defaults to private propagation.
- Propagation is an advanced bind-mount feature, not a simple shared-directory
  feature.
- Tinfoil's documented `volumes` field only shows simple bind syntax and does
  not document propagation options.

So a design that depends on "container A mounts something later and container B
sees it through an existing bind mount" is much more fragile than it first
appears.

### 5. Networked Filesystem Semantics Add Operational Complexity

If the storage container exports a real filesystem protocol such as NFS, we now
own more than storage:

- export configuration
- identity and ownership mapping
- reconnect behavior
- lock semantics
- startup race handling
- stale-handle and partial-failure recovery

That might still be worth it, but it is much heavier than "another container
manages files."

### 6. The Attestation Boundary Changes

A sidecar-managed storage design changes what is stable and what is mutable.

- The container images and config remain part of the attested deployment.
- The data served by the storage sidecar is mutable runtime state.
- That is acceptable for user state, caches, and working files.
- It is a bad fit for security-critical code, trusted configuration, or
  anything that should remain tied to the measured boot image.

So the design must keep a hard line between:

- attested code and boot configuration
- mutable runtime data provided by the storage sidecar

### 7. Failure Handling Gets More Subtle

Once `openclaw` depends on a managed filesystem, these failure cases matter:

- storage export is not ready when `openclaw` starts
- storage export becomes unavailable after `openclaw` is already serving
- storage sidecar restarts while `openclaw` still holds open files
- storage initialization succeeds partially
- `auth-proxy` believes bootstrap succeeded, but `openclaw` still cannot access
  the expected path

This usually means the control plane must do more than "call bootstrap once."
It needs a clear readiness signal for the storage path that `openclaw` will
actually use.

### 8. Security and Secret Handling Become Part of Bootstrap

If the storage path is network-backed, bootstrap may need to carry more than
today's `ANTHROPIC_API_KEY`.

Potential examples:

- storage endpoint information
- export name or dataset identifier
- mount options
- credentials or access tokens

The current bootstrap flow in this repo is intentionally narrow. Expanding it
for storage is feasible, but it increases the amount of sensitive runtime state
that has to be validated, transported, and failure-checked correctly.

## What Is Simpler Than a Real Network Mount

If the main goal is "let another container manage state for `openclaw`," there
are easier designs than a true cross-container filesystem mount.

### Option A: Storage Sidecar as an Application Service

`persistent-storage` exposes HTTP, WebDAV, or a small custom RPC API.

Pros:

- no in-container mount needed
- no bind propagation dependency
- easier to gate with healthchecks and bootstrap
- easier to reason about on Tinfoil

Cons:

- `openclaw` no longer sees a native filesystem path
- callers need explicit read/write/copy logic

### Option B: Mount Exists Before `openclaw` Starts

Treat the mount as boot-time state, not live-mutated state.

Pros:

- much closer to the documented mount model
- simpler failure story
- simpler `openclaw` assumptions

Cons:

- not a true hot handoff
- requires `openclaw` startup sequencing or restart after preparation

### Option C: Shared Directory Without a Real Filesystem Mount

If the storage container only needs to prepare files, not create a new mounted
filesystem, then both containers can point at the same shared directory and
bootstrap can wait until the directory contents are ready.

Pros:

- operationally much simpler
- avoids NFS and mount propagation

Cons:

- the storage container is managing files, not really "owning a filesystem"
- less isolation between storage logic and consumer logic

## Recommended Design Direction For This Repo

For this repo, the lowest-risk Tinfoil-compatible direction is:

1. keep `auth-proxy -> bootstrap -> openclaw` as the control plane
2. add a `persistent-storage` sidecar only if it exposes a clear readiness
   signal
3. prefer an application-level storage interface over a true in-container
   network mount
4. if a real filesystem path is mandatory, make sure the path exists before
   `openclaw` starts rather than relying on a live post-start handoff

The design to avoid is:

- `openclaw` starts
- another container performs a later mount
- `openclaw` is expected to see that new filesystem live through an already
  established mount path

That is exactly where Docker mount semantics, propagation, and undocumented
Tinfoil behavior become the main source of risk.

## Open Questions

These points would need direct validation before committing to a mount-based
design on Tinfoil:

- Does Tinfoil support any form of startup ordering beyond healthchecks?
- Does Tinfoil support bind propagation options on `volumes`?
- Does Tinfoil support any safe equivalent of mount-capable containers?
- Can a prepared mount be made available to another container without relying
  on undocumented host behavior?

Until those answers are explicit, the safest assumption is:

- healthchecks are available
- static bind mounts are available
- live filesystem handoff between sibling containers is not a documented
  platform feature

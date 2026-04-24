# Storage Options

This note is only about the storage layer for stateful OpenClaw on Tinfoil.

## What We Need

The storage layer must provide:

- authenticated encryption
- integrity over metadata and contents
- rollback protection
- a normal filesystem view for OpenClaw

## Options

### 1. Custom storage layer over blob storage plus freshness log

Shape:

- encrypted blobs for file data
- authenticated metadata / manifests
- freshness tracked by a counter or Merkle root

Pros:

- fits Tinfoil directly
- keeps OpenClaw unchanged
- easiest way to make rollback protection explicit

Cons:

- we have to build it

Status:

- recommended default

### 2. Gramine encrypted files

Pros:

- good model for encrypted, integrity-protected files
- useful reference for Merkle-protected file data

Cons:

- not enough by itself for rollback protection after close
- not Tinfoil-native

Status:

- useful reference, not the full solution

### 3. SCONE volumes / CAS model

Pros:

- closest conceptual match to what we want
- explicitly thinks in terms of encrypted state plus freshness tags

Cons:

- tied to SCONE runtime and control plane
- not a direct drop-in for this Tinfoil container

Status:

- good design reference, not the direct implementation

### 4. immudb

Pros:

- good fit for storing the latest accepted state root or counter
- append-only and verifiable

Cons:

- not a filesystem layer
- does not solve state encryption by itself

Status:

- useful as the freshness component, not the whole storage layer

## Recommendation

Use a custom storage layer for OpenClaw state, and optionally pair it with a small append-only freshness service.

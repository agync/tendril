---
type: Decision
title: "0001 One core, hostile paths"
description: Single Rust core with thin bindings, untrusted path providers, and separated pairing confirmation and capability grants.
status: stable
tags: [adr, architecture, security]
---

# 0001 One core, hostile paths

## Context

Personal devices need private, direct communication across changing networks (home LANs, overlays, cellular CGNAT, and browsers) without delegating trust to a central service or reimplementing cryptographic protocols in every host language.

## Decision

- **One Rust core, thin bindings.** Implement identity, pairing, sealed sessions, capability grants, and path selection once in Rust. Expose the core to Go, Python, TypeScript (Node and browser WASM), Swift, and Kotlin through thin wrappers tested against shared conformance vectors.
- **Providers are untrusted byte pipes.** Treat local sockets, direct TCP, overlays, peer-to-peer links, relays, and proxy brokers uniformly as hostile transport beneath one Noise XX session.
- **Separate confirmation from authority.** Confirming a peer's identity (`pair.confirm`) pins its key in the roster as a distinct step from granting capabilities (`pair.mint`). Grants follow default-deny semantics with explicit expiration and revocation.
- **Relay ladder without vendor lock-in.** Ship a default public relay configuration for first-run connectivity alongside self-hosted and embedded relay options on the same protocol. Changing relays rebuilds the session without re-pairing.
- **Pull-first delivery.** Support request, response, and polling over active connections first; treat mobile push wake signals as an optional future provider.
- **Apache-2.0 licensing.** Publish the specification, core, bindings, and relay components under Apache-2.0.

## Consequences

- Security audits, protocol fixes, and new capability rules land once in the Rust core instead of across six language implementations.
- Any binding or independent implementation must pass the shared conformance vector and fault-injection suite before release.
- Browser clients inherit platform constraints (WSS and polling only, no raw UDP, no held background links), documented explicitly as product limits rather than hidden behind abstractions.

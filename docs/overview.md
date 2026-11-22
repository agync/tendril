---
type: Overview
title: What Tendril is
description: Purpose, scope, non-goals, and explicit design limits.
status: draft
tags: [overview, architecture]
---

# What Tendril is

Tendril is a reusable SDK for establishing private, end-to-end encrypted links between devices without relying on a trusted third party. A single Rust core owns device identity, pairing verification, sealed hybrid post-quantum Noise sessions (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, hybrid Ed25519 + ML-DSA-65 signatures), default-deny capability grants, and path selection, while thin bindings expose that core to host languages over pluggable, untrusted path providers.

## Design summary

| Concern | Approach |
|---|---|
| Trust boundary | One Rust core owns keys, roster, sessions, grants, and path policy |
| Network paths | Providers are untrusted byte pipes ranked by locality and reliability |
| Authority | Confirmation of identity and minting of capabilities are distinct steps; default deny |
| Groups | A signed manifest names up to 32 devices; every sibling link is its own pairwise hybrid PQ session |
| Packaging | Thin bindings for Rust, Go, Python, TypeScript (Node and Web WASM), Swift, and Kotlin |
| Relay model | Public relay out of the box, with self-hosted and embedded relays on the same protocol |

## Scope

In scope:

- Pairwise encrypted links between desktop, phone, browser, and server endpoints
- Human-verified pairing via short code and SAS/fingerprint comparison, plus opt-in machine-to-machine (M2M) single-use token enrollment with trust anchors
- Signed, expiring, revocable capability grants checked on connection and on every authorized action
- Pluggable providers spanning local, direct, overlay, peer-to-peer, relay, and broker paths
- Small peer mesh groups of up to 32 devices: a signed membership manifest over independent pairwise sessions, with revocation and rendezvous-key rotation (see [Small peer mesh groups](design/groups.md))

Out of scope for v1 (tracked in [ADR 0003](adr/0003-v2-privacy-profile.md) for v2):

- Group-wide shared keys and multi-party group encryption (groups are pairwise links under a signed manifest, not a shared key)
- Anonymous routing, epoch-blinded relay mailboxes, packet padding, and timing-resistant cover traffic
- Hosted user accounts or mandatory cloud control planes
- Replacing TLS for general public web browsing

## Explicit limits and v1 tradeoffs

- **Sleeping mobile devices.** Operating systems suspend background sockets; pull works when awake, and push is an optional wake signal only.
- **Browser platform limits.** Web clients run the core in WASM over WebSockets and polling without raw UDP or reliable background links.
- **Relay visibility and v1 metadata.** Relays cannot read or forge sealed frames, but v1 observes static mailbox `device_id` strings, unpadded ciphertext lengths, and keepalive/rekey timing; operators should use self-hosted relays and `serve --redact-logs` where event log confidentiality matters, with wire-level privacy hardening scoped to v2 ([ADR 0003](adr/0003-v2-privacy-profile.md)).
- **Offline revocation.** A revoked peer cannot learn of its revocation until it attempts to reconnect or rekey.

---
type: Overview
title: What Tendril is
description: Purpose, scope, non-goals, and explicit design limits.
status: draft
tags: [overview, architecture]
---

# What Tendril is

Tendril is a reusable SDK for establishing private, end-to-end encrypted links between devices without relying on a trusted third party. A single Rust core owns device identity, pairing verification, sealed Noise sessions, default-deny capability grants, and path selection, while thin bindings expose that core to host languages over pluggable, untrusted path providers.

## Design summary

| Concern | Approach |
|---|---|
| Trust boundary | One Rust core owns keys, roster, sessions, grants, and path policy |
| Network paths | Providers are untrusted byte pipes ranked by locality and reliability |
| Authority | Confirmation of identity and minting of capabilities are distinct steps; default deny |
| Packaging | Thin bindings for Rust, Go, Python, TypeScript (Node and Web WASM), Swift, and Kotlin |
| Relay model | Public relay out of the box, with self-hosted and embedded relays on the same protocol |

## Scope

In scope:

- Pairwise encrypted links between desktop, phone, browser, and server endpoints
- Human-verified pairing via short code and fingerprint comparison, plus later machine-to-machine token enrollment
- Signed, expiring, revocable capability grants checked on connection and on every authorized action
- Pluggable providers spanning local, direct, overlay, peer-to-peer, relay, and broker paths

Out of scope for v1:

- Multi-party group encryption and shared group rosters
- Anonymous routing or traffic-analysis resistance
- Hosted user accounts or mandatory cloud control planes
- Replacing TLS for general public web browsing

## Explicit limits

- **Sleeping mobile devices.** Operating systems suspend background sockets; pull works when awake, and push is an optional wake signal only.
- **Browser platform limits.** Web clients run the core in WASM over WebSockets and polling without raw UDP or reliable background links.
- **Relay visibility.** Relays cannot read or forge sealed frames, but they observe endpoints, frame counts, sizes, and timing.
- **Offline revocation.** A revoked peer cannot learn of its revocation until it attempts to reconnect or rekey.

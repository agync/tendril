---
type: Decision
title: "0002 V1 protocol profile and Sans-I/O core"
description: Frozen Tendril v1 wire domain separators, transcript-bound pairing proof and SAS, humane retry limits, Sans-I/O core split, and minimal stateless WSS relay protocol.
status: stable
tags: [adr, wire, pairing, architecture, relay]
---

# 0002 V1 protocol profile and Sans-I/O core

> **Amended by [ADR 0004](0004-hybrid-post-quantum-v1.md):** `ADR 0004` replaced classical `Noise_XX_25519_ChaChaPoly_SHA256` and pure Ed25519 signatures in wire v1 with mandatory `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` (hybrid X25519 + ML-KEM-768) and hybrid `Ed25519 + ML-DSA-65` signatures, with no classical fallback.

## Context

[ADR 0001](0001-one-core-hostile-paths.md) established the top-level split between one Rust trust core, thin language bindings, and untrusted path providers. Before writing normative wire specifications, conformance vectors, and core state machines, five protocol and crate-boundary choices needed resolution:

1. Wire domain separators and pairing key-derivation salt ownership.
2. Separation between static key identifiers and live pairing verification checks.
3. Pairing code lifetimes, retry budgets, and when capability minting occurs.
4. Separation of pure protocol state from async I/O, FFI, and mobile key custody.
5. Relay transport protocol boundaries for browser and self-hosted deployments.

## Decision

### 1. Tendril-native wire domain separators and handshake-bound salt

Tendril defines its own neutral v1 wire domain separators with a single fixed cryptographic suite and bounded `uint16_be` framing model (amended from pure classical X25519/Ed25519 to mandatory hybrid `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` and hybrid `Ed25519 + ML-DSA-65` in [ADR 0004](0004-hybrid-post-quantum-v1.md)).

| Element | V1 Specification |
|---|---|
| Preamble (6 bytes, Noise prologue) | `"TND"` (`0x54 0x4E 0x44`), version `0x01`, intent (`0x01` session, `0x02` pair), reserved `0x00` |
| Outer frame layout | `uint16_be len \|\| body` with `0 <= len <= 65519` (`0xFFEF`, leaving 16 bytes for the AEAD tag) |
| Pairing proof (`code_mac`) | `HMAC-SHA256(key, "tendril-pair-v1" \|\| h)` where `h` is the 32-byte post-`msg2` handshake hash |
| Pairing KDF | `argon2id(code_norm, salt = h[..16], t = 3, m = 65536 KiB, p = 1, keyLen = 32, version = 0x13)` |
| Inner transport frame types | `u8 type`: `0x01 DATA`, `0x02 GRANT`, `0x03 REVOCATION`, `0x04 REKEY`, `0x05 PING`, `0x06 PONG`, `0x07 CLOSE` |
| Key rotation signature input | `"tendril-rot-v1\0" \|\| seq_be8 \|\| prev_signing_pub \|\| new_signing_pub \|\| new_static_pub \|\| ts_be8` |
| Capability grant signature input | `"tendril-grant-v1\0" \|\| rfc8785_jcs_json` (`uses` optional, reserved for single-use enrollment tokens) |

Binding the `argon2id` salt to `h[..16]` guarantees uniqueness per handshake without requiring host identifiers to meet minimum UTF-8 byte lengths. Including a monotonic `seq` counter in signed rotation records makes forked rotation chains explicitly detectable and immediately revocable.

### 2. Distinct static key fingerprints and transcript SAS

Static identity fingerprints and active pairing verification codes serve different security roles and must not share an ambiguous format.

| Check | Input | Format | Purpose |
|---|---|---|---|
| Host key fingerprint | `SHA-256(host_static_pub)` | 16 lowercase RFC 4648 base32 chars (`xxxx xxxx xxxx xxxx`) | Roster and pre-handshake key identity |
| Device key fingerprint | `SHA-256(device_static_pub)` | 16 uppercase hex chars (`XXXX XXXX XXXX XXXX`) | Roster and host confirmation UI |
| Pairing SAS | `SHA-256("tendril-sas-v1" \|\| h)` | Four 4-char lowercase base32 groups (optional deterministic word-list rendering) | Post-`msg2` active MITM check |

Distinct alphabets prevent users from confusing a host fingerprint with a device fingerprint during confirmation.

### 3. Humane pairing TTL and decoupled confirmation/minting

- Default pairing code lifetime is **15 minutes** (host-configurable), with a maximum of **5 failed claim attempts** across the lifetime of a code before it burns.
- The `pair` handshake completes immediately after verifying `code_mac` and records the peer as `pending`.
- Human fingerprint/SAS confirmation (`pair.confirm`) and capability minting (`pair.mint`) happen asynchronously on the host rather than holding the pairing connection open during human review. Grants are delivered or fetched once a `session` opens.

### 4. Pure Sans-I/O core separated from async runtime

- `tendril-core` implements all cryptographic state, pairing verification, Noise XX framing, capability grant evaluation, rotation checks, and path policy as a pure **Sans-I/O** state machine (`#![forbid(unsafe_code)]`, explicit virtual clock, zero OS sockets, zero async runtime).
- `tendril-runtime` drives `tendril-core` over Tokio sockets, path providers, LRU pre-auth rate limiters, and roster persistence.
- `tendril-ffi` exposes an opaque-handle, polled event queue C ABI with zero re-entrant FFI callbacks. `tendril-wasm` drives `tendril-core` directly in browsers.
- On mobile platforms lacking native Curve25519 enclave support, X25519 and Ed25519 keys are generated inside `tendril-core`, wrapped with OS Keychain or Android Keystore AES keys, and zeroized on drop.

### 5. Minimal Tendril-native stateless WSS relay

- Define a minimal, stateless WebSocket ciphertext forwarding protocol (`spec/relay-v1.md`) for public, self-hosted, and embedded relays.
- Mailbox registration uses stateless Ed25519 challenge-response proof of possession (`"tendril-relay-reg-v1\0" || relay_host || nonce`) so peers cannot hijack another peer's relay slot.
- Keep `iroh` dedicated to the `p2p` rung rather than coupling browser WSS relays to external relay conventions.

## Consequences

- Phase 0 freezes canonical byte vectors directly under `"TND"` without legacy domain strings or mixed framing rules.
- One Sans-I/O protocol implementation serves Tokio services, C FFI consumers, browser WASM builds, and deterministic fault-injection tests identically.
- Decoupling pairing from confirmation and minting avoids mobile handshake deadline failures while humans compare fingerprints and pick capability scopes.
- The minimal WSS relay specification keeps the browser path thin and self-hosting trivial as one embeddable crate.

---
type: Decision
title: "0004 Hybrid post-quantum cryptography in v1"
description: Mandatory Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256 key exchange and hybrid Ed25519 + ML-DSA-65 signatures directly in pre-1.0 wire v1.
status: stable
tags: [adr, crypto, post-quantum, wire, pairing, security]
---

# 0004 Hybrid post-quantum cryptography in v1

## Context

[ADR 0002](0002-v1-protocol-profile-and-sans-io-core.md) originally specified `Noise_XX_25519_ChaChaPoly_SHA256` and pure Ed25519 signatures for Tendril wire v1 (`0x01`). Before 1.0 release compatibility freezes the wire format, harvest-now-decrypt-later quantum adversaries pose an asymmetric risk to long-lived device-to-device links, stored grants, and rotation histories: recorded Noise ciphertexts from classical X25519 handshakes become decryptable later, whereas migrating early while pre-1.0 avoids dual-stack protocol complexity and classical downgrade surfaces.

Six design questions required resolution:

1. **Mandatory profile vs. versioned negotiation:** Whether to upgrade wire v1 (`0x01`) directly before 1.0 release or support runtime suite negotiation (`classical` vs. `hybrid`).
2. **Algorithm selection:** Which hybrid KEM and digital signature instantiations minimize total bandwidth while fitting comfortably within Tendril's `65,519`-byte Noise frame budget and pure-Rust WASM target (`wasm32-unknown-unknown`).
3. **Handshake transcript ownership:** Replacing `snow` (`NoSnow`) cleanly without reintroducing classical-only fallback code.
4. **Keeping `tendril://pair` QR codes compact:** Carrying raw `1984`-byte hybrid public keys in QR URIs exceeds dense mobile QR usability budgets.
5. **Relay control authentication boundary:** Whether untrusted ciphertext relays need ML-DSA-65 verification on `register`/`accept`.
6. **Independent cross-implementation verification:** Preventing single-implementation blind spots in `fips203`/`fips204`.

## Decision

### 1. Mandatory hybrid post-quantum suite directly in wire `0x01`

Pre-1.0 Tendril v1 (`WIRE_VERSION = 0x01`) mandates one fixed hybrid cryptographic suite with zero classical downgrade path or algorithm negotiation:

- **Key exchange and session encryption:** `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, replacing `snow` with an in-tree pure-Rust Sans-I/O implementation in `crates/tendril-core/src/noise.rs` combining `x25519-dalek` and NIST FIPS 203 `fips203` (`ml_kem_768`):
  - `msg1 -> e, e1`: `1216` bytes (`32 B` X25519 ephemeral + `1184 B` ML-KEM-768 encapsulation key, empty payload).
  - `msg2 <- e, ee, ekem1, s, es`: `1200 + len(HostHello)` bytes (`32 B` `e` + `1104 B` encrypted `ekem1` + `48 B` encrypted `s` + `HostHello` + `16 B` tag), carrying the host's `1984`-byte hybrid `signing_pub`.
  - `msg3 -> s, se`: `64 + len(payload)` bytes (`48 B` encrypted `s` + payload + `16 B` tag).
  - Both handshake and transport writers (`NoiseTransport::write_message_vec`) enforce `MAX_FRAME_LEN` (`65,519` B) before encrypting or incrementing AEAD nonces.
- **Hybrid identity signatures:** Fixed concatenation `Ed25519 (32 B pub / 64 B sig) || ML-DSA-65 (1952 B pub / 3309 B sig)` (`1984`-byte public keys, `3373`-byte signatures), with FIPS 204 context string `HYBRID_MLDSA_CTX = "tendril-hybrid-v1"` via `fips204`, required across grants, delegated chains, CRLs, `4031`-byte `RotationRecord` transcripts, and M2M `enroll_proof` claims. Verification requires both Ed25519 strict verification and ML-DSA-65 verification to succeed.

### 2. Compact QR pinning via `HostHello.signing_pub` + `sh=` SHA-256 pins

To keep `tendril://pair?v=1&...` QR URIs scannable without weakening authentication:

- Pairing URIs replace `s=<32B>` with `sh=<b64url(SHA-256(host_signing_pub))>` (`32` bytes), represented in `tendril-core` as `SigningKeyPin::{Full(HybridSigningPublicKey), Hash([u8; 32])}`.
- Encrypted `msg2` (`HostHello`) transmits the responder's full `1984`-byte `signing_pub`, which the initiator validates against its `SigningKeyPin` (and any `RotationRecord` chain) before emitting `msg3`, persisting the resolved full key once verified.
- M2M `enroll_initiate` accepts either the full `1984`-byte `signing_pub` or the `32`-byte `signing_pub_hash` exposed in endpoint `info_json`.

### 3. Relay control plane retains 32-byte Ed25519 prefix (`relay_pub`)

Stateless WebSocket relays (`spec/relay-v1.md`) remain untrusted ciphertext forwarders with zero visibility into plaintext, grants, or Noise session keys. Relay `register` and `accept` proofs continue using only the 32-byte Ed25519 prefix (`relay_pub`) and 64-byte Ed25519 challenge-response signatures, keeping control frames compact while end-to-end `Noise_XXhfs` and hybrid signing protect confidentiality and identity end-to-end.

### 4. Independent Go verification

`spec/vectors/verify_go` verifies every canonical test vector independently using Go standard library `crypto/mlkem` (`crypto/mlkem/mlkemtest`), `github.com/cloudflare/circl/sign/mldsa/mldsa65`, and an independent Go `Noise_XXhfs` implementation sharing zero code with Rust `tendril-core`.

## Consequences and measured release overhead

All release sizes below were measured directly on Linux `x86_64` (`lto = "thin"`, `codegen-units = 1`, `strip = true`):

| Artifact | Configuration | Measured Size | Pre-PQ Baseline / Delta |
|---|---|---|---|
| `target/release/libtendril_ffi.so` | `--no-default-features` | `4,834,416` B (`4.61 MiB`) | `4,052,248` B (+`763.8 KiB`) |
| `target/release/libtendril_ffi.so` | Default (`p2p-iroh`) | `15,196,176` B (`14.49 MiB`) | `14,606,424` B (+`575.9 KiB`) |
| `target/release/tendril` | `tendril-cli` default (`p2p-iroh`) | `17,836,408` B (`17.01 MiB`) | - |
| `bindings/web/pkg/tendril_wasm_bg.wasm` | Sans-I/O release (`gzip -9`) | `1,027,782` B raw / `363,833` B gzip (`355.3 KiB`) | `782,671` B raw / `292,452` B gzip (+`69.7 KiB` gzip) |
| `bindings/web/pkg-p2p/tendril_wasm_bg.wasm` | `p2p-iroh` release (`gzip -9`) | `4,279,199` B raw / `1,565,104` B gzip (`1.49 MiB`) | `4,116,121` B raw / `1,519,232` B gzip (+`44.8 KiB` gzip) |

- **Zero classical downgrade surface:** Pre-1.0 peers reject pre-PQ `HostHello` (missing `signing_pub`), classical Noise transcripts, and 32-byte/64-byte grants or rotation signatures immediately.
- **Handshake latency and bandwidth impact:** Initial `Noise_XXhfs` handshakes move roughly `~6 KiB` total across `msg1`/`msg2`/`msg3` (well below `65,519` B), adding negligible latency relative to Argon2id (`~106 ms` desktop browser) and P2P ICE setup while preventing retrospective decryption of recorded sessions.
- **State persistence upgrade:** Endpoints persist the `32`-byte ML-DSA-65 seed (`pq_signing_seed_b64` in CLI/runtime state and sealed browser/FFI state stores) alongside the Ed25519 seed, zeroized in memory on drop.

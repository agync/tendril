---
type: Reference
title: Conformance vectors
description: Canonical JSON test vectors and cross-language verification targets under spec/vectors/.
status: stable
tags: [reference, conformance, vectors]
---

# Conformance vectors

Every language binding and independent implementation must match all canonical vectors byte-for-byte.

## Vector files

| File | Verified Primitives | Negative Cases |
|---|---|---|
| `spec/vectors/fingerprints.json` | `device_id`, `host_fingerprint`, `device_fingerprint`, `pairing_sas` | Invalid key length rejection |
| `spec/vectors/pairing_mac.json` | 3-group and 2-group normalization, `argon2id`, `code_mac`, human signing key proof (`key_proof`) | Wrong-code constant-time rejection; key proof over another `h` |
| `spec/vectors/rotation.json` | `seq = 1` and `seq = 2` 4031-byte binary hybrid signatures (`Ed25519 + ML-DSA-65`) and chain bridge | Duplicate `seq` fork detection and unanchored fork rejection |
| `spec/vectors/grants.json` | RFC 8785 JCS canonicalization, hybrid signature, valid delegation, signed CRL | Widened child scope and forged non-root issuer rejection |
| `spec/vectors/handshake.json` | Full deterministic `pair` and `session` `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` transcripts, `DATA`, and `REKEY` | Unverified `msg2` host key or pin mismatch abort before `msg3` |
| `spec/vectors/m2m_enrollment.json` | Signed single-use `pair.enroll` token, 3373-byte hybrid `enroll_proof`, M2M `PairClaim` and `PairResponse` | Single-use replay rejection and session-grant purpose-separation rejection |
| `spec/vectors/wire_v2.json` | Wire `0x02` preamble binding, PAKE `Argon2id` + HKDF derivation, pseudonymous rendezvous MAC, `/v2/relay` epoch `mailbox_id`/`dial_token`, `0x09 PADDED` buckets | Stale/replayed rendezvous rejection, downgrade floor rejection, and invalid padding rejection |

## Verification commands

```bash
cargo run -p tendril-core --example gen_vectors   # regenerate spec/vectors/*.json
make vectors/check                                # run Rust and Go verifiers
make check                                        # run full workspace quality gate
```

Both `crates/tendril-core/tests/vectors.rs` (Rust) and `spec/vectors/verify_go/vectors_test.go` (Go) execute during `make vectors/check`.

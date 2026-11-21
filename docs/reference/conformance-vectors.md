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
| `spec/vectors/pairing_mac.json` | 3-group and 2-group normalization, `argon2id`, `code_mac` | Wrong-code constant-time rejection |
| `spec/vectors/rotation.json` | `seq = 1` and `seq = 2` 127-byte binary signatures and chain bridge | Duplicate `seq` fork detection and unanchored fork rejection |
| `spec/vectors/grants.json` | RFC 8785 JCS canonicalization, grant signature, valid delegation, signed CRL | Widened child scope and forged non-root issuer rejection |
| `spec/vectors/handshake.json` | Full deterministic `pair` and `session` Noise XX transcripts, `DATA`, and `REKEY` | Unverified `msg2` host key abort before `msg3` |
| `spec/vectors/m2m_enrollment.json` | Signed single-use `pair.enroll` token, `enroll_proof`, M2M `PairClaim` and `PairResponse` | Single-use replay rejection and session-grant purpose-separation rejection |

## Verification commands

```bash
cargo run -p tendril-core --example gen_vectors   # regenerate spec/vectors/*.json
make vectors/check                                # run Rust and Go verifiers
make check                                        # run full workspace quality gate
```

Both `crates/tendril-core/tests/vectors.rs` (Rust) and `spec/vectors/verify_go/vectors_test.go` (Go) execute during `make vectors/check`.

# Tendril Conformance Specification v1

Status: **Normative (v1)**

A core library, language binding, or independent protocol implementation conforms to Tendril v1 only when it passes all three conformance layers below.

---

## 1. Conformance Layers

| Layer | Purpose | Verification Artifact |
|---|---|---|
| **1. Canonical Vectors** | Byte-for-byte agreement on hashes, KDF, signatures, canonical JSON, and Noise transcripts | `spec/vectors/*.json` |
| **2. Live Transcript Interop** | Cross-language handshakes, pairing, grants, rekey, rotation, and revocation against a reference peer | `tendril-conformance-peer` (Phase 2-3) |
| **3. Adversarial Fault Injection** | Clean fail-closed termination with zero panics under malformed or malicious inputs | Adversarial test suite (Phase 1+) |

---

## 2. Canonical Vector Files (`spec/vectors/`)

Every vector file is generated deterministically from real cryptographic primitives (`cargo run -p tendril-core --example gen_vectors`) and verified independently by both Rust (`crates/tendril-core/tests/vectors.rs`) and Go (`spec/vectors/verify_go/vectors_test.go`).

| File | Contents & Negative Cases |
|---|---|
| `fingerprints.json` | Static pubkeys -> `device_id`, `host_fingerprint`, `device_fingerprint`; post-`msg2` `h` -> `pairing_sas` |
| `pairing_mac.json` | 3-group remote (`TND-XXXX-XXXX-XXXX`) and 2-group LAN (`TND-XXXX-XXXX`) codes, normalized forms, `argon2id` keys, and `code_mac` values |
| `rotation.json` | Sequential hybrid signed `RotationRecord` links (`seq = 1`, `seq = 2`), exact 4031-byte raw signed payloads, plus a conflicting `seq = 2` fork vector that MUST trigger revocation |
| `grants.json` | Unsorted input grant -> exact RFC 8785 JCS canonical bytes + hybrid Ed25519 / ML-DSA-65 signature; valid delegated child grant; invalid widened-scope child grant that MUST fail; signed `RevocationList` |
| `handshake.json` | Deterministic `intent = pair` and `intent = session` `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` transcripts (`preamble`, `msg1` [1216 B], `msg2` carrying `HostHello.signing_pub`, post-`msg2` `h`, `pairing_sas`, `code_mac`, `msg3`, final hash, encrypted `DATA`, encrypted `REKEY`, and post-rekey encrypted `DATA`) |
| `m2m_enrollment.json` | Signed single-use `pair.enroll` token, hybrid Ed25519 + ML-DSA-65 channel-binding `enroll_proof` (3373 B), post-`msg2` M2M `PairClaim`, verified `"active"` `PairResponse`, and negative replay / wrong-purpose rejection cases |

Canonical hybrid PQ verification in `spec/vectors/verify_go` uses Go stdlib `crypto/mlkem` (`crypto/mlkem/mlkemtest`), `github.com/cloudflare/circl/sign/mldsa/mldsa65`, and an independent Go `Noise_XXhfs` implementation sharing zero code with `tendril-core`.

---

## 3. Running Vector Verification

```bash
make vectors/check    # runs Rust vector tests and independent Go vector tests
make check            # full repository gate including vectors/check
```

Any change to wire formats, cryptographic parameters, canonicalization, or domain separators MUST regenerate `spec/vectors/*.json` and pass both the Rust and Go suites in the same commit.

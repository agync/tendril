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
| `rotation.json` | Sequential signed `RotationRecord` links (`seq = 1`, `seq = 2`), exact 127-byte raw signed payloads, plus a conflicting `seq = 2` fork vector that MUST trigger revocation |
| `grants.json` | Unsorted input grant -> exact RFC 8785 JCS canonical bytes + signature; valid delegated child grant; invalid widened-scope child grant that MUST fail; signed `RevocationList` |
| `handshake.json` | Deterministic `intent = pair` and `intent = session` `Noise_XX` transcripts (`preamble`, `msg1`, `msg2`, post-`msg2` `h`, `pairing_sas`, `code_mac`, `msg3`, final hash, encrypted `DATA`, encrypted `REKEY`, and post-rekey encrypted `DATA`) |

---

## 3. Running Vector Verification

```bash
make vectors/check    # runs Rust vector tests and independent Go vector tests
make check            # full repository gate including vectors/check
```

Any change to wire formats, cryptographic parameters, canonicalization, or domain separators MUST regenerate `spec/vectors/*.json` and pass both the Rust and Go suites in the same commit.

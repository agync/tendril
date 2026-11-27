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

Every vector file is generated deterministically from real cryptographic primitives (`cargo run -p tendril-core --example gen_vectors`; `groups.json` uses `--example gen_group_vectors`) and verified independently by both Rust (`crates/tendril-core/tests/vectors.rs`) and Go (`spec/vectors/verify_go/vectors_test.go`).

| File | Contents & Negative Cases |
|---|---|
| `fingerprints.json` | Static pubkeys -> `device_id`, `host_fingerprint`, `device_fingerprint`; post-`msg2` `h` -> `pairing_sas` |
| `pairing_mac.json` | 3-group remote (`TND-XXXX-XXXX-XXXX`) and 2-group LAN (`TND-XXXX-XXXX`) codes, normalized forms, `argon2id` keys, and `code_mac` values; `key_proof`: signing key claim bytes (`"tendril-pair-key-v1\0"`), deterministic hybrid `enroll_proof`, and the keyed human `PairClaim` (a proof over another `h` MUST fail) |
| `rotation.json` | Sequential hybrid signed `RotationRecord` links (`seq = 1`, `seq = 2`), exact 4031-byte raw signed payloads, plus a conflicting `seq = 2` fork vector that MUST trigger revocation |
| `grants.json` | Unsorted input grant -> exact RFC 8785 JCS canonical bytes + hybrid Ed25519 / ML-DSA-65 signature; valid delegated child grant; invalid widened-scope child grant that MUST fail; signed `RevocationList` |
| `handshake.json` | Deterministic `intent = pair` and `intent = session` `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` transcripts (`preamble`, `msg1` [1216 B], `msg2` carrying `HostHello.signing_pub`, post-`msg2` `h`, `pairing_sas`, `code_mac`, `msg3`, final hash, encrypted `DATA`, encrypted `REKEY`, and post-rekey encrypted `DATA`); `session_refusal_v1` (Section 4.1) |
| `groups.json` | `group_id` derivation, six-manifest chain (root-signed and co-admin-signed with `admin_grant`) with exact JCS signed bytes and hybrid signatures, rejections (scope escape, cross-group capability, rollback, revoked re-add, co-admin removing the root, wire downgrade, 33 members, oversize, `group_id` mismatch, expiry, tampering), forged co-admin with a swapped key, bare admin grant, `seq = 2^53`, sequence jump, removal without revocation, co-admin rewriting the root entry, `%` and `\` in capability resources, and explicit `null` optionals, `pair_bootstrap` and `group_mailbox` HKDF outputs, the 60-byte `0x0B` frame, and `SessionHello.groups` |
| `wire_v2.json` | Wire v2 preambles, blinded `/v2/relay` epoch tokens, relay admission, pseudonymous reconnect, and PAKE pairing; `v2_refusal` (Section 4.1) |
| `m2m_enrollment.json` | Signed single-use `pair.enroll` token, hybrid Ed25519 + ML-DSA-65 channel-binding `enroll_proof` (3373 B), post-`msg2` M2M `PairClaim`, verified `"active"` `PairResponse`, and negative replay / wrong-purpose rejection cases |

Canonical hybrid PQ verification in `spec/vectors/verify_go` uses Go stdlib `crypto/mlkem` (`crypto/mlkem/mlkemtest`), `github.com/cloudflare/circl/sign/mldsa/mldsa65`, and an independent Go `Noise_XXhfs` implementation sharing zero code with `tendril-core`.

---

## 3. Running Vector Verification

```bash
make vectors/check    # runs Rust vector tests and independent Go vector tests
make check            # full repository gate including vectors/check
```

Any change to wire formats, cryptographic parameters, canonicalization, or domain separators MUST regenerate `spec/vectors/*.json` and pass both the Rust and Go suites in the same commit.

---

## 4. Authenticated Refusal

Authenticated refusal is specified in `spec/wire-v1.md` Sections 3.3 and 5.4, `spec/wire-v2.md` Sections 3.1.3 to 3.1.5 and 5.1, and `spec/pairing-v1.md` Section 5.1.

### 4.1 Vectors

| File | Block | Contents |
|---|---|---|
| `wire_v2.json` | `v2_refusal` | Inputs `reconnect_secret`, `rendezvous_nonce`, `h_pre` and `bucket`; for codes `4001` and `4004`, `refusal_seal_key_hex` and `sealed_refusal_hex`. Negatives that MUST fail: an open under `hello_seal_key` and a hello open under `refusal_seal_key`, `version != 0x01`, non-zero padding, and code `4002` |
| `handshake.json` | `session_refusal_v1` | A deterministic Wire v1 session transcript with a revoked initiator, and the 21-byte encrypted `0x07 CLOSE 4001` frame the responder writes |

The Go verifier (`spec/vectors/verify_go`) derives `refusal_seal_key` independently, opens `sealed_refusal`, checks the padding, and decrypts the Wire v1 `CLOSE` frame.

### 4.2 Required Behaviour

An implementation that sends or receives refusals MUST pass each case below. `REF-nn` identifiers are stable.

| ID | Wire | Case | Expected |
|---|---|---|---|
| `REF-01` | v1 | Revoked, v1-floored initiator with a live notice | Responder writes one 21-byte frame, `CLOSE 4001` with empty text, and emits no `Established`. Initiator reports `Established`, then a close with code `4001` |
| `REF-02` | v1 | Pending initiator, pending notices on | As `REF-01` with code `4004` |
| `REF-03` | v1 | Stranger (no roster entry) | No bytes after `msg2`; the responder's behaviour is unchanged from before refusals |
| `REF-04` | v1 | `active` entry revoked by a stored CRL; then revoked with `notify: false`, an expired notice, and a rate-limited second attempt | `CLOSE 4001` for the first; no bytes after `msg2` for the others |
| `REF-05` | v2 | Revoked initiator with a live notice | Initiator fails with `PeerRefused(Revoked)` at `msg2` and writes no `msg3`. The `msg2` remote static is not the host's static key |
| `REF-06` | v2 | Genuine, decoy and refusal `msg2`, with and without a rotation chain | Identical `msg2` length in each configuration |
| `REF-07` | v2 | Pending initiator holding `v2_secrets` | `PeerRefused(Pending)` at `msg2` |
| `REF-08` | v2 | Refusal-class `msg1` with a stale `ts`, a nonce already in either replay cache, or a full `RefusalReplayCache` | Decoy `msg2`; the refusal limiter is not charged |
| `REF-09` | v2 | Initiator that implements only the `hello_seal_key` open receives a refusal | `HostKeyUnverified` |
| `REF-10` | v2 | Opened refusal with a bad version, `len != 3`, non-zero padding, code `4002`, a length outside `V2_HANDSHAKE_BUCKETS`, or a low-order remote static | `ProtocolViolation`; no `msg3` |
| `REF-11` | v2 | Entry revoked between `msg1` and `msg3`, default padding and padding disabled | Initiator sees a close with code `4001` after `Established`. With padding disabled the frame is a bare `0x07`, not `UnknownInnerFrameType` |
| `REF-15` | v1 | Refused initiator on a TCP stream sends `DATA` right after it reports `Established` | It still receives the close with code `4001`, not a connection reset |
| `REF-16` | both | Two refusal-class attempts by one peer within `10 s` | The first is refused, the second is silent; at most one refusal audit record |
| `REF-19` | v1 | v2-floored `pending` and `revoked` entries connect over `0x01` | `VersionDowngrade`; 0 bytes after `msg2` |
| `REF-20` | v2 | A revoked peer sends `MAX_RENDEZVOUS_REPLAY_ENTRIES + 100` fresh `msg1` | An `active` peer still connects |
| `REF-21` | both | A revoked or pending ordinary peer probes a group listener, then the endpoint's ordinary dispatcher | Decoy or silent drop at the group listener; refusal at the dispatcher |
| `REF-22` | v2 | A revoked entry's refusal secret equals an `active` sibling's secret, in either roster order; a CRL-revoked entry with rendezvous alternates | `Silent` in both orders (identity collision, `spec/wire-v2.md` Section 3.1.3.1); the alternates never yield `Genuine` |
| `REF-23` | v1 | 16 refused peers, then a 17th `active` handshake on an untrusted provider | The `active` handshake is admitted |
| `REF-24` | both | Close codes `4002`, `4003` and `1000` received by an initiator; `4450` received by an initiator; `4001` received by a responder | No refusal for the first three; `Other(4450)`; the responder keeps the raw code |

IDs `REF-12` to `REF-14`, `REF-17` and `REF-18` are reserved for implementation tests (roster storage, secret accessors, runtime candidate racing, C ABI and bindings) that do not define wire behaviour.

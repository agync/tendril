# Tendril Pairing Specification v1

Status: **Normative (v1)**

Conventions follow `spec/wire-v1.md`.

---

## 1. Identity Keys and Platform Custody

Each Tendril endpoint maintains two long-lived cryptographic keypairs:

| Key | Algorithm | Size | Role |
|---|---|---|---|
| Static keypair | X25519 | 32 B private scalar, 32 B public | Noise `s` key; identifies peer across sessions |
| Signing keypair | Ed25519 | 32 B private seed, 32 B public | Signs grants, rotation records, CRLs, and relay registrations |

On platforms whose hardware enclaves do not support Curve25519 directly (for example Apple Secure Enclave or Android StrongBox P-256 enclaves), X25519 and Ed25519 keys are generated in `tendril-core`, persisted wrapped by OS Keychain or Android Keystore AES keys, and zeroized from memory on drop.

---

## 2. Deterministic Identifiers and Human Verification Formats

### 2.1 Device ID

```text
device_id = "dev_" || hex_lower(SHA-256(static_pub)[0..8])
```

- `static_pub` is the raw 32-byte X25519 static public key.
- Result is always 20 ASCII characters (`dev_` plus 16 lowercase hex chars).

### 2.2 Static Key Fingerprints (Roster and Pre-Handshake Pinning)

Host and device key fingerprints deliberately use disjoint character alphabets so an operator never confuses which peer's key is displayed:

```text
host_fingerprint   = group4(first16(lowercase(base32_nopad(SHA-256(host_static_pub)))))
device_fingerprint = group4(first16(uppercase(hex(SHA-256(device_static_pub)))))
```

- `base32_nopad` uses RFC 4648 standard base32 (`A-Z2-7`, no padding `=`).
- `group4` inserts a single ASCII space (`0x20`) after every 4 characters: `xxxx xxxx xxxx xxxx` (host) and `XXXX XXXX XXXX XXXX` (device).

### 2.3 Post-Handshake Transcript SAS

During live pairing, both peers compute a Short Authentication String (SAS) bound to the post-`msg2` Noise handshake hash `h` (32 bytes):

```text
sas_digest  = SHA-256("tendril-sas-v1" || h)
pairing_sas = group4(first16(lowercase(base32_nopad(sas_digest))))
```

- `"tendril-sas-v1"` is the exact 14-byte ASCII label (`0x74 65 6e 64 72 69 6c 2d 73 61 73 2d 76 31`) followed directly by the 32-byte `h` (46 bytes total).
- Implementations MAY additionally render a deterministic 3-word mnemonic derived from `sas_digest`, with the `4x4` base32 form remaining the canonical conformance representation.

---

## 3. Pairing Codes and Normalization

### 3.1 Code Alphabet and Forms

Pairing codes are drawn uniformly from the 31-character unambiguous ASCII alphabet:

```text
23456789ABCDEFGHJKMNPQRSTUVWXYZ
```

| Form | Format | Random Chars | Approximate Entropy | Intended Path |
|---|---|---|---|---|
| QR / LAN | `TND-XXXX-XXXX` | 8 | 39.6 bits | QR scan or verified LAN path |
| Remote manual | `TND-XXXX-XXXX-XXXX` | 12 | 59.4 bits | Manual entry across remote/relay paths |

Hosts MUST reject a 2-group (`TND-XXXX-XXXX`) code when claimed over a remote or relay path unless explicitly permitted by host policy.

### 3.2 Normalization (Consensus-Critical)

Before key derivation, both initiator and responder MUST normalize the entered code:

1. Convert ASCII letters `a-z` to uppercase `A-Z`.
2. Strip all ASCII hyphen characters (`-`, `0x2D`).
3. Apply no whitespace trimming beyond UI input handling and no Unicode folding.

Example: `tnd-4f9k-22xq-8n3p` normalizes to `TND4F9K22XQ8N3P`.

---

## 4. Channel-Binding Proof (`code_mac`)

The pairing code NEVER crosses the wire. In `msg3` (`PairClaim`), the initiator proves possession of the code bound to the exact Noise handshake hash `h` obtained immediately after processing `msg2`:

```text
K = argon2id(
    password = UTF-8(code_normalized),
    salt     = h[0..16],
    t        = 3,
    m        = 65536,    // 64 MiB in KiB
    p        = 1,
    keyLen   = 32,
    version  = 0x13      // Argon2 v1.3
)

code_mac = HMAC-SHA256(key = K, msg = "tendril-pair-v1" || h)
```

- `salt` is the first 16 bytes of the 32-byte post-`msg2` Noise handshake hash `h`.
- `"tendril-pair-v1"` is the exact 15-byte ASCII label (`0x74 65 6e 64 72 69 6c 2d 70 61 69 72 2d 76 31`) concatenated directly with the 32-byte `h` (47 bytes total, no separator).
- Verification MUST compare the computed 32-byte MAC against `PairClaim.code_mac` using constant-time equality (`subtle::ConstantTimeEq`).

---

## 5. Pairing Lifecycle and State Transitions

```text
[unpaired] --(pair intent + valid code_mac)--> [pending] --(pair.confirm)--> [active] --(revoke)--> [revoked]
```

- **Default TTL:** 15 minutes (`900 s`), configurable by the host.
- **Retry budget:** At most **5** failed `pair` claim attempts per code lifetime. Because a wrong-code or MITM-relayed claim cannot be attributed to a single live code in constant time without leaking existence, every failed `pair` claim increments the failure counter on all currently live codes and burns any code reaching 5 failures. To prevent pairing-window status oracles, responders run a uniform dummy KDF pass when zero live codes exist and return the uniform `"unauthorized"` error code across invalid, expired, or burned pairing codes.
- **Single-use burn:** A successful `pair` claim immediately burns the matched code.
- **Re-pairing rules:**
  - Re-pairing an already `active` static key updates metadata if needed and stays `active`.
  - Re-pairing a `revoked` static key MUST fail (`Revoked`) and keep the peer `revoked`; the matched pairing code still burns so an attacker cannot probe live codes with a revoked device.
  - A peer in `pending` state MUST NOT open `intent = session` connections until an operator runs `pair.confirm` after comparing `device_fingerprint` and `pairing_sas`. Whenever a live pairing SAS was recorded during pairing, `pair.confirm` MUST require explicit SAS matching and MUST fail closed if omitted; out-of-band fingerprint-only confirmation requires an explicit opt-in API or flag (`--allow-no-sas`).
- **Grant separation:** `pair.confirm` marks the roster entry `active` with zero non-session grants by default. Minting capabilities (`pair.mint`) is an independent operation.
- **Symmetric client-side SAS gate & pin protection:**
  - When initiating pairing via an out-of-band pinned URI (`PinnedHost`), the initiator cryptographically verifies the responder's static/signing keys and rotation chain in `msg2` and may record the host pin directly as `active`.
  - When initiating manual unpinned pairing without a pre-shared host key pin, the client MUST record the newly learned host pin in `pending` state awaiting operator SAS confirmation (`pair.confirm`) before allowing `intent = session` connections.
  - Existing `active`, `pending`, or `revoked` host pins MUST NOT be overwritten with differing cryptographic keys during pairing (`host_id` collisions fail closed without retaining or transferring prior grants).

---

## 6. Pairing URI Scheme

```text
tendril://pair?v=1&host=<url_encoded_name>&code=<code>&k=<b64url_host_static>&s=<b64url_host_signing>[&id=<url_encoded_host_id>][&seq=<u64>][&ep=<csv>]
```

- `k` pins the host's valid full-order 32-byte X25519 static public key prior to `msg1` (small-subgroup points MUST be rejected).
- `s` pins the host's valid 32-byte Ed25519 signing public key as the rotation chain root (or current key at `seq`).
- `id` optionally pins the host's expected `host_id` carried in `HostHello`.
- `seq` optionally carries the host's current `rotation_seq` corresponding to `(k, s)`. When `seq` is omitted on a legacy URI for an already-rotated host presenting a contiguous chain from `seq == 1` ending at `(k, s)`, initiators MAY verify that chain and initialize the pin at `last.seq`.
- `ep` carries comma-separated endpoint hints (`<provider>:<addr>`), which are dialing hints only and never grant authorization.
- Strict URI validation: parsers MUST reject unknown query parameters, duplicate parameters, empty `host`/`code`/`id` values, ASCII control characters (`0x00..=0x1F`, `0x7F`), malformed pairing codes (expecting `TND-XXXX-XXXX` or `TND-XXXX-XXXX-XXXX`), and unsafe/unrecognized endpoint hints (`javascript:`, `file:`, `data:`, non-loopback cleartext `ws://`/`http://`, userinfo `@`, fragments, or link-local/metadata IP hints). `PairClaim` and `HostHello` display/identifier fields with control characters or empty required names MUST likewise fail closed.

---

## 7. Machine-to-Machine Enrollment Profile

Autonomous headless hosts and workload agents (Phase 6) may enroll without interactive human SAS comparison using a signed single-use enrollment token (`grants-v1.md`) trusted via a pinned host key on the initiator and registered trust anchors on the responder. M2M enrollment is disabled by default and MUST be enabled explicitly by responder policy.

### 7.1 Enrollment Token Format

An enrollment token is a signed `Grant` (`grants-v1.md`) satisfying ALL of the following:

- `v == 1`, `machine == true`, and `uses == 1`.
- `nonce` is a valid 16-byte `b64url` (unpadded, 22-character) unique token identifier.
- `not_after > not_before` and `not_after - not_before <= max_enrollment_ttl_secs` (default `900 s`, hard upper bound `86400 s`). Evaluation uses the standard `30 s` clock-skew tolerance on `not_before`.
- `caps` is non-empty and every capability MUST match `pair.enroll` or `pair.enroll:<host_id>`, where `<host_id>` equals the responder `host_id`. Zero application capabilities or other reserved capabilities are permitted on the leaf enrollment token.
- `subject` equals the enrolling peer's `device_id`, OR `"*"` when responder policy permits wildcard unbound subjects.
- Root signer (`issuer` of the root link when `delegated_from` is absent, or of the deepest ancestor link when `delegated_from` is present) MUST be either the responder itself (when responder policy allows self-issued enrollment tokens) or an `active` `TrustAnchor` registered in the responder `Roster`. Ancestor delegation links MUST hold `pair.mint`, MUST NOT set `uses` or `machine`, and MUST NOT share a signing key with any `revoked` trust anchor.
- All links and token `nonce` MUST pass verification against the active persisted `RevocationList` (`revoked_devices`, `revoked_nonces`) for the root issuer.

### 7.2 Channel-Binding Proof (`enroll_proof`)

In `msg3`, an M2M initiator omits `code_mac` and populates `enrollment_token`, `signing_pub` (b64url 32-byte Ed25519 public key matching `enroll_proof`), and `enroll_proof` (b64url 64-byte Ed25519 signature over the Noise transcript binding `h`, initiator static public key `peer_static_pub`, and `token.nonce`):

```text
enroll_proof_bytes = "tendril-enroll-v1\0" (18 B)
                  || h (32 B)
                  || peer_static_pub (32 B)
                  || UTF-8(enrollment_token.nonce)

enroll_proof = Ed25519(peer_signing_priv, enroll_proof_bytes)
```

Responders MUST verify `enroll_proof` strictly against `signing_pub` before accepting enrollment, ensuring the claim cannot be replayed into a different Noise session or substituted for a different static identity.

### 7.3 Initiator Pinning Requirement

M2M initiators MUST supply an out-of-band `PinnedHost` (static key, root/current signing key, `host_id`, optional `rotation_seq`) and verify the responder's `HostHello` (and `RotationRecord` chain if rotated) at `msg2` before transmitting `msg3`. Unpinned TOFU is forbidden in M2M mode.

### 7.4 Atomic Single-Use Burn Log and Default-Deny Roster Entry

- Responders persist `burned_enrollment_nonces` (`nonce -> not_after_unix`) alongside `Roster`, bounded at `16_384` active entries (`MAX_BURNED_ENROLLMENT_NONCES`). Expired entries (`not_after <= now`) are pruned before capacity checks; if all `16_384` slots remain unexpired, new enrollments fail closed (`EnrollmentBurnLogFull` / `"rate_limited"`).
- On a valid M2M `PairClaim`, the responder MUST atomically check and record `token.nonce` in `burned_enrollment_nonces` and persist the `Roster` BEFORE calling `record_enrolled_machine` and BEFORE writing `PairResponse` to the wire. If the enrolling peer static key is `Revoked` or collides with an existing entry, registration fails closed (`Revoked`), while the token nonce remains burned so a revoked device cannot probe live tokens.
- `record_enrolled_machine` transitions the peer directly into `Active` state with `(static_pub, signing_pub)` and zero application grants (`PairResponse.status = "active"`). Application authorization still requires separate `pair.mint` delegation.

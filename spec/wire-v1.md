# Tendril Wire Specification v1

Status: **Normative (v1)**

Conventions: `b64url` means unpadded URL-safe base64 (RFC 4648 Section 5, no `=`). `hex` means lowercase hexadecimal unless stated otherwise. All integers on the wire are big-endian (`be`). The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `MAY` are interpreted per RFC 2119.

---

## 1. Cipher Suite and Versioning

- Noise pattern (fixed): `Noise_XX_25519_ChaChaPoly_SHA256`.
- Wire version: `0x01`.
- Peers MUST reject any connection carrying an unsupported version or unknown intent.
- Outer transport security (TLS, WireGuard, peer-to-peer stream encryption, WSS) is treated as untrusted byte plumbing. Only the inner Noise session authenticates peers and carries authorization.

---

## 2. Cleartext Preamble and Outer Framing

### 2.1 Preamble (6 bytes, client to server)

Every connection opens with exactly 6 raw bytes sent by the initiator before the first framed message. The exact 6 bytes are fed verbatim as the Noise **prologue** on both sides before processing `msg1`.

```text
offset  bytes  field    value
0       3      magic    ASCII "TND" (0x54 0x4E 0x44)
3       1      version  0x01
4       1      intent   0x01 = session
                        0x02 = pair
5       1      rsvd     0x00 (MUST be 0x00)
```

Responders MUST close the connection immediately (and charge pre-auth rate limits) if `magic != "TND"`, `version != 0x01`, `intent` is not `0x01` or `0x02`, or `rsvd != 0x00`.

### 2.2 Length-Prefixed Framing (both directions, post-preamble)

All bytes after the 6-byte preamble are partitioned into discrete frames:

```text
frame = uint16_be len || body (len bytes)
```

- `len` MUST satisfy `0 <= len <= 65519` (`0xFFEF`).
- The ceiling `65519` reserves 16 bytes for the ChaCha20-Poly1305 AEAD tag beneath the 65535-byte Noise message ceiling.
- Receivers MUST inspect `len` and reject `len > 65519` before allocating a frame buffer.
- `len == 0` is a valid empty frame body (for example, an empty `Noise_XX` `msg1`).
- Transport readers MUST support resumable partial-frame reads across I/O deadlines so an interrupted read never desynchronizes frame boundaries.

---

## 3. Noise XX Handshake

```text
msg1  ->  e                  payload: empty (0-length frame body)
msg2  <-  e, ee, s, es       payload: HostHello (compact UTF-8 JSON, encrypted)
msg3  ->  s, se              payload: SessionHello | PairClaim (compact UTF-8 JSON, encrypted)
```

### 3.1 Handshake Payloads

```jsonc
// msg2 payload (responder -> initiator)
HostHello = {
  "host_id": string,                // stable host identifier
  "proto_version": 1,               // must equal 1
  "rotation"?: [RotationRecord]     // present only when extending a pinned key
}

// msg3 payload, intent = session (initiator -> responder)
SessionHello = {
  "device_id": string,              // "dev_" + hex_lower(SHA-256(static_pub)[..8])
  "grant"?: Grant,                  // optional grant presented at connect
  "crl_seq"?: uint64                // highest CRL sequence already cached by initiator
}

// msg3 payload, intent = pair (initiator -> responder)
// Human pairing sets code_mac and omits M2M fields.
// M2M enrollment omits code_mac and sets enrollment_token, signing_pub, and enroll_proof.
PairClaim = {
  "name": string,                   // human-readable device label
  "kind": string,                   // platform kind (e.g. "ios", "android", "cli", "web", "machine")
  "code_mac"?: string,              // b64url 32-byte HMAC-SHA256 proof (human pairing, pairing-v1)
  "enrollment_token"?: Grant,       // signed M2M enrollment Grant (grants-v1, pairing-v1 Section 7)
  "signing_pub"?: string,           // b64url 32-byte Ed25519 peer signing key (M2M enrollment)
  "enroll_proof"?: string           // b64url 64-byte Ed25519 channel-binding signature (M2M enrollment)
}
```

### 3.2 Pair Intent Response

When `intent == 0x02` (`pair`), after decrypting and processing `msg3`, the responder enters transport mode, writes **exactly one** encrypted outer frame carrying a compact UTF-8 JSON `PairResponse`, and closes the connection:

```jsonc
// success (human pairing: status == "pending"; M2M enrollment: status == "active")
{
  "device_id": string,
  "status": "pending" | "active",
  "host_signing_pub": string        // b64url 32-byte Ed25519 public key to pin
}

// failure
{
  "error": string                   // typed error code (e.g. "unauthorized", "token_expired", "token_replayed", "untrusted_anchor", "revoked", "rate_limited")
}
```

For human pairing, confirming the peer (`pair.confirm`) and minting capabilities (`pair.mint`) happen asynchronously on the host after human verification; the pairing connection is never held open waiting for operator input. For M2M enrollment (`pairing-v1.md` Section 7), a verified enrollment token transitions the peer directly to `"active"` with zero application grants (`pair.mint` remains a separate step).

### 3.3 Verification Order

**Initiator at `msg2` (before writing `msg3`):**

1. Decrypt `msg2` and decode `HostHello`; verify `proto_version == 1`.
2. For `intent = session`: verify responder static `s` (`current_static`) and `current_signing` (`pinned_signing` when `HostHello.rotation` is absent or empty, or `rotation.last().new_signing_pub` when non-empty): either `current_static == pinned_static` AND `current_signing == pinned_signing`, OR `HostHello.rotation` is a valid, contiguous `RotationRecord` chain linking `(pinned_signing, pinned_static)` to `(current_signing, current_static)` (where `current_static == rotation.last().new_static_pub`). If neither holds, MUST abort immediately (`HostKeyUnverified`) before sending `msg3` so the initiator's static key is never disclosed to an unverified peer.
3. For `intent = pair`: if a pinned host key was supplied out of band (for example via QR URI or mandatory M2M enrollment configuration), apply the same check as step 2 before sending `msg3`. M2M enrollment MUST NOT use unpinned TOFU. On manual human pairing with no pin, proceed using the post-`msg2` handshake hash `h` to bind `code_mac` and verify the transcript SAS.

**Responder:**

1. Validate the 6-byte preamble; drop and rate-limit on any invalid field.
2. Execute Noise `msg1`..`msg3`. Any AEAD failure drops the connection before interpreting payload fields.
3. For `intent = session`: verify the peer static key `s` from `msg3` belongs to an `active` roster entry and `SessionHello.device_id` equals the derived `device_id` of `s`. Reject `pending` or `revoked` peers.
4. For `intent = pair`: enforce mutual exclusion between `code_mac` and M2M enrollment fields (`enrollment_token`, `signing_pub`, `enroll_proof`). For human claims, verify `PairClaim.code_mac` per `pairing-v1.md` and register or update the peer as `pending`. For M2M claims (only when M2M enrollment is enabled by responder policy), verify the trust-anchored enrollment token, CRL, single-use nonce burn, and channel-bound `enroll_proof` per `pairing-v1.md` Section 7, burn the nonce atomically, and register the peer as `active` with zero application grants. Send `PairResponse` and close.

---

## 4. Signed Key Rotation (`RotationRecord`)

A host rotates its `(X25519 static, Ed25519 signing)` keypair by signing a `RotationRecord` with the outgoing Ed25519 signing key.

```jsonc
RotationRecord = {
  "seq": uint64,                    // strictly monotonic counter (>= 1, prev_seq + 1)
  "prev_signing_pub": string,       // b64url 32-byte outgoing Ed25519 public key
  "new_signing_pub": string,        // b64url 32-byte new Ed25519 public key
  "new_static_pub": string,         // b64url 32-byte new X25519 public key
  "ts": string,                     // RFC 3339 UTC timestamp at whole-second precision (YYYY-MM-DDTHH:MM:SSZ, no fractional seconds or numeric offsets)
  "sig": string                     // b64url 64-byte Ed25519 signature by prev_signing_pub
}
```

### 4.1 Exact Signed Bytes (127 bytes)

Signatures MUST cover the raw concatenated bytes below (NOT the JSON text), verified using strict Ed25519 verification:

```text
domain_prefix      (15 B) = ASCII "tendril-rot-v1\0" (0x74..0x31 0x00)
seq_be8            ( 8 B) = big-endian uint64(seq)
prev_signing_pub   (32 B) = raw outgoing Ed25519 public key
new_signing_pub    (32 B) = raw new Ed25519 public key
new_static_pub     (32 B) = raw new X25519 static public key
ts_be8             ( 8 B) = big-endian uint64 Unix seconds of ts (>= 1970-01-01T00:00:00Z)
```

### 4.2 Chain and Fork Detection Rules

- Each link MUST satisfy `seq == prev_seq + 1` (with `seq >= 1` for the first link) and `link.prev_signing_pub == prev.new_signing_pub`, with no repeated `signing_pub` cycles.
- Anchoring: when `chain` is non-empty, the link starting from `pinned_signing` MUST satisfy `seq == pinned_seq + 1` (or, if a peer already pinned the latest key and receives a historical prefix ending at `(pinned_signing, pinned_static, pinned_seq)`, the full chain MUST validate contiguously without forks or cycles).
- Fast path (no rotation records provided, `chain` empty): both `current_static == pinned_static` AND `current_signing == pinned_signing` MUST hold.
- Fork rule: if a verifier observes two distinct valid `RotationRecord`s sharing `(seq, prev_signing_pub)` where `prev_signing_pub` is `pinned_signing` or reachable from it through valid links with `seq > pinned_seq`, it MUST transition the peer entry immediately to `revoked`, reject the session, and raise a security alert. Unanchored records signed by unrelated keys fail chain verification without revoking the peer.

---

## 5. Inner Encrypted Transport Envelope (`intent = session`)

Inside Noise transport mode, each outer AEAD frame decrypts to a plaintext payload of at least 1 byte and at most `65503` bytes (`65519 - 16`):

```text
inner_frame = frame_type (1 byte) || payload (0..=65502 bytes)
```

Receivers MUST close the session immediately on a 0-byte transport plaintext or any unrecognized `frame_type`.

| `frame_type` | Name | Payload Layout | Semantics |
|---|---|---|---|
| `0x01` | `DATA` | `0..=65502 B` opaque app bytes | Delivered to application `recv()` stream |
| `0x02` | `GRANT` | Compact UTF-8 JSON `Grant` | Presents or updates a signed capability grant |
| `0x03` | `REVOCATION` | Compact UTF-8 JSON `RevocationList` | Synchronizes signed device/nonce revocations |
| `0x04` | `REKEY` | Empty (`0` bytes) | Triggers Noise `CipherState::rekey()` |
| `0x05` | `PING` | `8 B` big-endian `u64` cookie | Liveness probe; peer responds with `0x06 PONG` |
| `0x06` | `PONG` | `8 B` big-endian `u64` echoed cookie | Liveness response |
| `0x07` | `CLOSE` | `2 B` big-endian `u16` reason code + optional UTF-8 text | Graceful session close (`payload.len() >= 2`) |

### 5.1 Noise Rekey Mechanics

- A sender initiates rekeying by encrypting and sending an empty `0x04 REKEY` frame under the current outgoing cipher state, and MUST immediately call `rekey_outgoing()` afterwards so the next sent frame uses the rotated key.
- A receiver decrypts `0x04 REKEY` under the current incoming cipher state, MUST assert its payload is empty, MUST immediately call `rekey_incoming()`, and MUST re-check active session grants against the latest `RevocationList`.
- Peers SHOULD initiate `0x04 REKEY` automatically every `1_048_576` (`2^20`) sent frames or every `15` minutes of session lifetime, whichever occurs first.

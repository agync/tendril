# Tendril Wire Specification v1

Status: **Normative (v1)**

Conventions: `b64url` means unpadded URL-safe base64 (RFC 4648 Section 5, no `=`). `hex` means lowercase hexadecimal unless stated otherwise. All integers on the wire are big-endian (`be`). The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `MAY` are interpreted per RFC 2119.

---

## 1. Cipher Suite and Versioning

- Noise pattern (fixed): `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` (`fips203` ML-KEM-768 + X25519 + ChaCha20-Poly1305 + SHA-256).
- Identity signing suite (fixed): Hybrid `Ed25519 (32 B pub / 64 B sig) || ML-DSA-65 (1952 B pub / 3309 B sig)` = `1984`-byte public keys (`SHA-256` pin `32` bytes) and `3373`-byte signatures with ML-DSA-65 context `"tendril-hybrid-v1"`.
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
- The ceiling `65519` reserves 16 bytes for the ChaCha20-Poly1305 AEAD tag beneath the 65535-byte Noise message ceiling. Both handshake and transport writers MUST verify this frame length ceiling before advancing AEAD cipher state or incrementing nonces.
- Receivers MUST inspect `len` and reject `len > 65519` before allocating a frame buffer.
- `len == 0` is a valid empty frame body at the framing layer (note that `Noise_XXhfs` `msg1` is `1216` bytes).
- Transport readers MUST support resumable partial-frame reads across I/O deadlines so an interrupted read never desynchronizes frame boundaries.

---

## 3. Noise XXhfs Handshake

```text
msg1  ->  e, e1                 1216 B (32 B X25519 e || 1184 B ML-KEM-768 e1; empty payload)
msg2  <-  e, ee, ekem1, s, es   1200 + len(HostHello) B (32 B e || 1104 B ct || 48 B s || payload + 16 B tag)
msg3  ->  s, se                 64 + len(payload) B (48 B s || payload + 16 B tag)
```

### 3.1 Handshake Payloads

```jsonc
// msg2 payload (responder -> initiator)
HostHello = {
  "host_id": string,                // stable host identifier
  "proto_version": 1,               // must equal 1
  "signing_pub": string,            // b64url 1984-byte hybrid Ed25519 || ML-DSA-65 public key
  "rotation"?: [RotationRecord],    // present only when extending a pinned key
  "upgrade"?: [string]              // responder's enabled upgrade capabilities (1..=4 items, each 1..=32 bytes matching [a-z0-9._/-]); omitted when empty and during pairing
}

// msg3 payload, intent = session (initiator -> responder)
SessionHello = {
  "device_id": string,              // "dev_" + hex_lower(SHA-256(static_pub)[..8])
  "grant"?: Grant,                  // optional grant presented at connect
  "crl_seq"?: uint64,               // highest CRL sequence already cached by initiator
  "groups"?: [{ "group_id": string, "seq": uint64 }],  // group gossip summary (groups-v1 Section 9), 1..=16 entries, omitted when empty
  "route_seq"?: uint64,             // 0..=2^53-1; opt-in to 0x0C ROUTE_SET announcements (Section 5.2), omitted otherwise
  "upgrade"?: [string]              // negotiated upgrade capabilities (local ∩ HostHello.upgrade, 1..=4 items); omitted when empty
}

// msg3 payload, intent = pair (initiator -> responder)
// Human pairing sets code_mac, signing_pub, and enroll_proof (pairing-v1 Section 4.1) and omits enrollment_token.
// M2M enrollment omits code_mac and sets enrollment_token, signing_pub, and enroll_proof.
PairClaim = {
  "name": string,                   // human-readable device label
  "kind": string,                   // platform kind (e.g. "ios", "android", "cli", "web", "machine")
  "code_mac"?: string,              // b64url 32-byte HMAC-SHA256 proof (human pairing, pairing-v1)
  "enrollment_token"?: Grant,       // signed M2M enrollment Grant (grants-v1, pairing-v1 Section 7)
  "signing_pub"?: string,           // b64url 1984-byte hybrid Ed25519 || ML-DSA-65 peer signing key
  "enroll_proof"?: string,          // b64url 3373-byte hybrid Ed25519 || ML-DSA-65 channel-binding signature (pairing-v1 Section 4.1 or 7.2)
  "route_seq"?: uint64              // M2M only, 0..=2^53-1: requests PairResponse.route_set (pairing-v1 Section 7.5); omitted otherwise
}
```

### 3.2 Pair Intent Response

When `intent == 0x02` (`pair`), after decrypting and processing `msg3`, the responder enters transport mode, writes **exactly one** encrypted outer frame carrying a compact UTF-8 JSON `PairResponse`, and closes the connection:

```jsonc
// success (human pairing: status == "pending"; M2M enrollment: status == "active")
{
  "device_id": string,
  "status": "pending" | "active",
  "host_signing_pub": string,       // b64url 1984-byte hybrid Ed25519 || ML-DSA-65 public key to pin
  "route_set"?: string              // M2M only, when the claim carried route_seq: b64url 0x0C payload (Section 5.2.1), pairing-v1 Section 7.5; a human initiator rejects a reply that carries it
}

// failure
{
  "error": string                   // typed error code (e.g. "unauthorized", "token_expired", "token_replayed", "untrusted_anchor", "revoked", "rate_limited")
}
```

For human pairing, confirming the peer (`pair.confirm`) and minting capabilities (`pair.mint`) happen asynchronously on the host after human verification; the pairing connection is never held open waiting for operator input. For M2M enrollment (`pairing-v1.md` Section 7), a verified enrollment token transitions the peer directly to `"active"` with zero application grants (`pair.mint` remains a separate step).

### 3.3 Verification Order

**Initiator at `msg2` (before writing `msg3`):**

1. Decrypt `msg2` and decode `HostHello`; verify `proto_version == 1` and decode `HostHello.signing_pub` as a valid `1984`-byte hybrid signing key (`current_signing`). If `intent == 0x02` (`pair`), `HostHello.upgrade` MUST be empty or omitted. For `intent = session`, validate `HostHello.upgrade` and compute `local ∩ HostHello.upgrade` to send in `SessionHello.upgrade` (omitting `upgrade` when empty).
2. For `intent = session`: verify responder static `s` (`current_static`) and `current_signing` against the stored pin `(pinned_signing, pinned_static, pinned_seq)` (where `pinned_signing` may be a full `1984`-byte key or a `32`-byte `SHA-256` hash pin): either `current_static == pinned_static` AND `pinned_signing` matches `current_signing`, OR `HostHello.rotation` is a valid, contiguous `RotationRecord` chain linking `(pinned_signing, pinned_static)` at `pinned_seq` to `(current_signing, current_static)` (where `current_static == rotation.last().new_static_pub` and `current_signing == rotation.last().new_signing_pub`). If neither holds, MUST abort immediately (`HostKeyUnverified`) before sending `msg3` so the initiator's static key is never disclosed to an unverified peer.
3. For `intent = pair`: if a pinned host key was supplied out of band (for example via QR URI `sh=` hash pin or mandatory M2M enrollment configuration), apply the same check as step 2 before sending `msg3` (and persist the newly resolved full `1984`-byte `current_signing` key when verified from a hash pin). M2M enrollment MUST NOT use unpinned TOFU. On manual human pairing with no pin, proceed using the post-`msg2` handshake hash `h` to bind `code_mac` and verify the transcript SAS.
4. When the pin comes from a pairing URI that carries `rp`, `rq` or `rs`, or the connect supplies an operator relay key (`URL#key`), run the relay key check (`spec/pairing-v1.md` Section 6.4) against the authenticated `HostHello.signing_pub` and then the route statement check (Section 6.5), in that order and after step 3, before sending `msg3`. For `intent = session` with a recovery URI or an operator relay key, run the session variant of those checks (`spec/pairing-v1.md` Section 6.5): the relay key check applies to the operator `URL#key` even when no URI is supplied, and runs after the rotation chain verifies and before applying the rotation or sending `msg3`. A failure aborts without writing `msg3`.

**Responder:**

1. Validate the 6-byte preamble; drop and rate-limit on any invalid field.
2. Execute Noise `msg1`..`msg3`. Any AEAD failure drops the connection before interpreting payload fields.
3. For `intent = session`: verify `SessionHello.device_id` equals the derived `device_id` of the peer static key `s` from `msg3`, then resolve `s` as below and act on the first matching row of the table. Only an `active` resolution continues. Reject `SessionHello.upgrade` if it contains any capability not advertised in `HostHello.upgrade`.

   Resolution of `s` considers every roster entry and every pending host claim (`spec/pairing-v1.md` Section 5) whose static key is `s`, and never depends on roster key order:

   - **Floor:** the effective floor is the highest `min_wire_version` across all of those records. When it is above `1`, the responder fails closed before any admission or refusal, so it never writes a transport frame to a peer whose floor forbids `0x01`.
   - **State, revoked wins:** `s` resolves as revoked when any matching entry is `revoked`, when a matching `active` entry is revoked by a stored CRL, or when a matching `active` entry shares its signing identity with a `revoked` entry. Otherwise it resolves as `active` when a matching entry is `active`, otherwise as `pending` when a matching entry is `pending`, otherwise as not found.
   - **Notice:** when `s` resolves as revoked, a notice is live when any matching entry that is not manifest-pinned (a group sibling pin) carries a live refusal notice (`spec/pairing-v1.md` Section 5.1). An `active` entry revoked by a stored CRL counts as carrying a live notice while `revoked_notice_ttl_secs` is not `0`.

   | Resolution of `s` | Action |
   |---|---|
   | effective floor above `1` (any state) | fail closed (`VersionDowngrade`) and drop; **0 bytes** written after `msg2` (`spec/wire-v2.md` Section 1.1) |
   | `active` | continue the session |
   | revoked; a live notice as defined above; the refusal limiter allows (Section 5.4.2); the listener is refusal-enabled (Section 5.4.3) | enter transport mode, send one `0x07 CLOSE` with code `4001 peer_revoked`, then run the refusal close sequence (Section 5.4.4) |
   | `pending`; no matching `pending` entry is manifest-pinned; pending notices enabled (`spec/pairing-v1.md` Section 5.1); the refusal limiter allows; the listener is refusal-enabled | enter transport mode, send one `0x07 CLOSE` with code `4004 peer_pending`, then run the refusal close sequence |
   | revoked or `pending` with no live notice or pending notices off, a manifest-pinned entry, rate-limited, or on a listener that is not refusal-enabled | drop; 0 bytes written after `msg2` |
   | no matching entry, or any other failure | drop; 0 bytes written after `msg2` |

   A responder MUST NOT emit `Established` for a refused peer. A stranger (no matching entry) never receives a `0x07 CLOSE`: its connection is dropped with the same bytes and the same code path as before this rule.
4. For `intent = pair`: enforce mutual exclusion between `code_mac` and `enrollment_token`. For human claims, verify `PairClaim.code_mac` per `pairing-v1.md`, then verify the signing key claim (`signing_pub`, `enroll_proof`) per `pairing-v1.md` Section 4.1 when present, and record the peer per the Section 4.1 recording rules (a new entry, or an `active` entry the claim adds a key to, becomes `pending`; any other accepted claim keeps the entry's state). A Wire v1 responder built before that section rejects a keyed human claim as `protocol_error`; initiators MUST NOT retry without the proof (pre-1.0 break). For M2M claims (only when M2M enrollment is enabled by responder policy), verify the trust-anchored enrollment token, CRL, single-use nonce burn, and channel-bound `enroll_proof` per `pairing-v1.md` Section 7, burn the nonce atomically, and register the peer as `active` with zero application grants. When the claim carried `route_seq`, add the host-signed `route_set` per `pairing-v1.md` Section 7.5. Send `PairResponse` and close.

---

## 4. Signed Key Rotation (`RotationRecord`)

A host rotates its `(X25519 static, hybrid Ed25519 + ML-DSA-65 signing)` keypair by signing a `RotationRecord` with the outgoing hybrid signing key.

```jsonc
RotationRecord = {
  "seq": uint64,                    // strictly monotonic counter (>= 1, prev_seq + 1)
  "prev_signing_pub": string,       // b64url 1984-byte outgoing hybrid public key
  "new_signing_pub": string,        // b64url 1984-byte new hybrid public key
  "new_static_pub": string,         // b64url 32-byte new X25519 public key
  "ts": string,                     // RFC 3339 UTC timestamp at whole-second precision (YYYY-MM-DDTHH:MM:SSZ, no fractional seconds or numeric offsets)
  "sig": string                     // b64url 3373-byte hybrid Ed25519 || ML-DSA-65 signature by prev_signing_pub
}
```

### 4.1 Exact Signed Bytes (4031 bytes)

Signatures MUST cover the raw concatenated bytes below (NOT the JSON text), verified using both strict Ed25519 verification and ML-DSA-65 verification with context `"tendril-hybrid-v1"`:

```text
domain_prefix      (  15 B) = ASCII "tendril-rot-v1\0" (0x74..0x31 0x00)
seq_be8            (   8 B) = big-endian uint64(seq)
prev_signing_pub   (1984 B) = raw outgoing hybrid public key (32 B Ed25519 || 1952 B ML-DSA-65)
new_signing_pub    (1984 B) = raw new hybrid public key (32 B Ed25519 || 1952 B ML-DSA-65)
new_static_pub     (  32 B) = raw new X25519 static public key
ts_be8             (   8 B) = big-endian uint64 Unix seconds of ts (>= 1970-01-01T00:00:00Z)
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

Receivers MUST close the session immediately on a 0-byte transport plaintext or any unrecognized `frame_type`. A `0x0A` payload above `32768` bytes or a `0x0B` payload that is not exactly `60` bytes MUST be rejected (`GroupManifestTooLarge`, `InvalidInnerFramePayload`). The `0x0C` receive rule is Section 5.2.3 alone: it decides direction, negotiation, drop and close for that tag, and no rule of this section adds a rejection to it.

`SessionHello` is sent by the initiator only. Peers built before the optional `groups` field reject it as an unknown field (`deny_unknown_fields`); initiators therefore omit `groups` when they hold no groups, and this incompatibility is accepted before 1.0. The optional `route_seq` field follows the same rule (Section 5.2).

| `frame_type` | Name | Payload Layout | Semantics |
|---|---|---|---|
| `0x01` | `DATA` | `0..=65502 B` opaque app bytes | Delivered to application `recv()` stream |
| `0x02` | `GRANT` | Compact UTF-8 JSON `Grant` | Presents or updates a signed capability grant |
| `0x03` | `REVOCATION` | Compact UTF-8 JSON `RevocationList` | Synchronizes signed device/nonce revocations |
| `0x04` | `REKEY` | Empty (`0` bytes) | Triggers Noise `CipherState::rekey()` |
| `0x05` | `PING` | `8 B` big-endian `u64` cookie | Liveness probe; peer responds with `0x06 PONG` |
| `0x06` | `PONG` | `8 B` big-endian `u64` echoed cookie | Liveness response |
| `0x07` | `CLOSE` | `2 B` big-endian `u16` reason code (Section 5.4) + optional UTF-8 text | Graceful session close (`payload.len() >= 2`); a refusal code closes a session the responder never admitted (Section 5.4) |
| `0x0A` | `GROUP_MANIFEST` | Compact UTF-8 JSON `GroupManifest`, `<= 32768 B` | Pushes or gossips a signed group manifest (`spec/groups-v1.md`); surfaced to the caller, never auto-ingested |
| `0x0B` | `GROUP_RENDEZVOUS` | `20 B` ASCII `group_id` `\|\|` `8 B` big-endian `u64` `seq` `\|\|` `32 B` key, exactly `60 B` | Delivers a group rendezvous key from an admin to a member (`spec/groups-v1.md` Section 7) |
| `0x0C` | `ROUTE_SET` | `route_set_body \|\| sig`, `3455..=5003 B` (Section 5.2) | Host-signed route announcement, responder to initiator only (`spec/pairing-v1.md` Section 6.11) |
| `0x0D` | `PATH_UPGRADE` | Compact UTF-8 JSON `PathUpgradeMsg`, `<= 16384 B` (Section 5.3) | In-band authenticated upgrade signaling (e.g. WebRTC SDP offer/answer/reject) |

### 5.1 Noise Rekey Mechanics

- A sender initiates rekeying by encrypting and sending an empty `0x04 REKEY` frame under the current outgoing cipher state, and MUST immediately call `rekey_outgoing()` afterwards so the next sent frame uses the rotated key.
- A receiver decrypts `0x04 REKEY` under the current incoming cipher state, MUST assert its payload is empty, MUST immediately call `rekey_incoming()`, and MUST re-check active session grants against the latest `RevocationList`.
- Peers SHOULD initiate `0x04 REKEY` automatically every `1_048_576` (`2^20`) sent frames or every `15` minutes of session lifetime, whichever occurs first.

### 5.2 Route Set Announcement (`0x0C ROUTE_SET`)

A responder (host) tells a paired initiator (client) which routes it currently advertises. The statement is signed by the host's hybrid signing key, so a relay or on-path attacker cannot forge or reorder it. Acceptance, persistence and replay rules are in `spec/pairing-v1.md` Section 6.11.

#### 5.2.1 Exact Signed Bytes and Payload

```text
route_set_body =
  version     ( 1 B)  0x01
  static_pub  (32 B)  host Noise static public key (current)
  sh          (32 B)  SHA-256 of the host's current 1984-byte hybrid signing public key
  seq         ( 8 B)  uint64_be, 1..=2^53-1
  issued_at   ( 8 B)  uint64_be, Unix seconds
  count       ( 1 B)  0..=6
  routes      (var)   count times: len (2 B uint16_be, 1..=256) || hint (len bytes UTF-8)

route_set_signed_bytes = "tendril-route-set-v1\0" (21 B) || route_set_body
sig      (3373 B) = hybrid Ed25519 || ML-DSA-65 signature over route_set_signed_bytes (ML-DSA-65 context "tendril-hybrid-v1")
0x0C payload       = route_set_body || sig
```

- Bounds: `route_set_body` is `82..=1630` bytes; the payload is `3455..=5003` bytes (`MAX_ROUTE_SET_PAYLOAD = 5003`); the signed bytes are at most `1651` bytes.
- Each hint passes the pairing endpoint hint syntax (`spec/pairing-v1.md` Section 6.1), contains no `#`, is not `local:` or `unix://`, and appears once. Hints appear in announced-set order (`spec/pairing-v1.md` Section 6.11.1). `count = 0` is valid: the host currently advertises nothing.
- The Ed25519 half is produced by the same Ed25519 identity key that signs the pairing URI route statement; the ML-DSA-65 half makes the in-session statement post-quantum, like rotation records. Verification requires both halves strictly.
- Deterministic test vectors are in `spec/vectors/routes.json`.

#### 5.2.2 Negotiation and Direction

| Item | Rule |
|---|---|
| Direction | Responder to initiator only. A responder that receives `0x0C` MUST close the session (`InvalidInnerFramePayload("route set from initiator")`). |
| Opt-in | The initiator sets `SessionHello.route_seq` (`0..=2^53-1`) to signal that it understands `0x0C` and applies announcements. The value is the stored route sequence when that sequence came from an announcement or an approved replacement, else `0` (a sequence learned only from a URI, so the host's equal-sequence set may still add hints the QR trimmed). It is fixed before `msg3` is built. A Wire v2 initiator with padding disabled omits `route_seq`, because `0x0C` arrives only inside `0x09 PADDED`. |
| When an initiator sends it | Only when the effective route policy is `all_signed` and the target entry has route metadata (it once verified a signed URI or announcement from this host). Under `committed_only` or `none`, or without metadata, the field is omitted. |
| When the host sends | (a) Once right after the session is established, before any other host-initiated frame, iff the client sent `route_seq` and the host's current `seq > route_seq`. (b) Mid-session after a change of its advertised set, to every live session whose client sent `route_seq`. |
| Host rate limit | Per session: changes are debounced `2 s` and coalesced (the latest set wins); at most one `0x0C` per `30 s` after the first. |
| Client rate limit | Per session: at most one `0x0C` processed per `10 s`; extra frames inside the window are dropped before signature verification. |
| Wire v2 | `0x0C` travels only inside `0x09 PADDED` (`spec/wire-v2.md` Section 5.1). A session with padding disabled neither sends nor receives it. Before sealing, the host checks that the session's padding policy has a bucket of at least `4 + payload_len` bytes; if not, it does not send `0x0C` on that session (the failure is recorded locally) and keeps the session open. The default buckets always fit. |

#### 5.2.3 Receive-Check Order

After AEAD decryption and (Wire v2) `0x09` unpadding, receivers run these checks in order:

1. **Tag.** `0x0C` is a known inner frame type. Only the generic `MAX_TRANSPORT_PLAINTEXT` bound applies at this step; there is no per-type length check here.
2. **Direction.** A responder closes the session (`InvalidInnerFramePayload("route set from initiator")`).
3. **Negotiation.** An initiator that did not send `route_seq` drops the frame here, before any payload byte is parsed: no decode, no close, no queue.
4. **Structure.** A payload outside `3455..=5003` bytes, a bad length prefix, `count > 6`, a hint length of `0` or over `256`, a hint that fails the rules above (syntax, `#`, `local:` or `unix://`, duplicates), a `seq` of `0` or above `2^53-1`, a `version` other than `0x01`, or trailing bytes closes the session (`InvalidInnerFramePayload("route set")`), matching `0x0A` and `0x0B`.
5. **Queue.** At most `4` decoded sets are queued for the application layer; older entries are dropped. `0x0C` payloads are never delivered to the application stream.
6. **Semantics.** The rate limit, then the acceptance rules of `spec/pairing-v1.md` Section 6.11.3 (signature, key binding, sequence, issue time, policy).

Semantic rejections (rate-limit drops, bad signature, key mismatch, stale sequence, future issue time, policy) never close the session; the receiver records the reason locally. Structural failures (step 4) close the session, but only for an initiator that sent `route_seq`: an initiator that omitted it has already dropped the frame at step 3, so a malformed `0x0C` never reaches step 4 on that session and is neither parsed nor rejected. Apart from that negotiation drop (step 3), no structural failure is ignored and no semantic failure closes.

#### 5.2.4 Compatibility

- Hosts built before this frame reject `SessionHello.route_seq` as an unknown field (`deny_unknown_fields`). A client sends it only to a host that already signed a route set, which only new hosts do, so the only break is a host downgraded after signing; this is accepted before 1.0, as for `SessionHello.groups`.
- Clients built before this frame never send `route_seq`, so a conforming host never sends them `0x0C` and their close-on-unknown-frame rule is never triggered.
- A new client that receives `0x0C` without having sent `route_seq` drops it at step 3 without closing and without parsing, well-formed or malformed.

### 5.3 In-Band Direct Path Upgrade (`0x0D PATH_UPGRADE`)

An initiator and responder connected over a non-direct path (such as a relay) may negotiate in-band direct upgrade signaling inside the authenticated Noise session (`UPGRADE_CAP_WEBRTC_V1 = "webrtc/v1"`):

1. **Negotiation (`HostHello.upgrade` / `SessionHello.upgrade`):** The responder advertises its enabled upgrade capabilities (up to `MAX_UPGRADE_CAPS = 4` distinct ASCII strings, each `1..=32` bytes matching `[a-z0-9._/-]`) in `HostHello.upgrade`, omitting the field when empty (`intent = pair` MUST keep `HostHello.upgrade` empty/omitted). The initiator computes `local ∩ HostHello.upgrade` and sends the negotiated subset in `SessionHello.upgrade` (omitted when empty), and the responder MUST fail closed if `SessionHello.upgrade` contains any capability not offered in `HostHello.upgrade`. An explicit `"upgrade": []` JSON array is invalid and rejected by decoders (`upgrade` MUST be omitted when empty).
2. **Framing and Limits:** `0x0D PATH_UPGRADE` carries a compact UTF-8 JSON `PathUpgradeMsg` (`type: "offer" | "answer" | "reject"`, `upgrade_id` in `1..=2^53-1`, `protocol` matching `[a-z0-9._/-]`, `sdp` `1..=MAX_PATH_UPGRADE_SDP_LEN` (`15360` bytes, no NUL bytes), or `reason` `1..=256` bytes without ASCII control characters) whose serialized JSON size is `1..=MAX_PATH_UPGRADE_LEN` (`16384` bytes).
3. **Direction, Correlation, and Rate Limits:** `Offer` is initiator -> responder only; `Answer` and `Reject` are responder -> initiator only. An initiator MAY send at most `MAX_PATH_UPGRADE_OFFERS_PER_SESSION = 4` offers per session; peers correlate pending `(upgrade_id, protocol)` pairs (`Answer.protocol` MUST match the pending offer's `protocol`) and fail closed (`InvalidInnerFramePayload` or `ProtocolViolation`) on wrong-direction frames, unnegotiated or mismatched protocols, stale/unsolicited `upgrade_id` replies, or excess offers.
4. **Cutover Security:** For `"webrtc/v1"`, the initiator opens an ordered binary DataChannel named `"tendril/v1"` (`WEBRTC_DATACHANNEL_LABEL`), then runs a fresh `Noise_XXhfs` session handshake against the same pinned peer identity over that DataChannel before cutting over traffic. ICE and DTLS alone never replace Tendril's end-to-end Noise identity and AEAD confidentiality.
5. **Compatibility:** Because `HostHello` enforces `deny_unknown_fields`, enabling responder `upgrade` advertisement is opt-in and requires clients that recognize `HostHello.upgrade`. Conversely, upgrade-capable initiators remain backward-compatible with older hosts that omit `HostHello.upgrade`, because `SessionHello.upgrade` carries only the intersection and omits the field when empty.

### 5.4 Close Codes and Authenticated Refusal

#### 5.4.1 Close Code Registry

The `0x07 CLOSE` reason code is one of the values below. This registry applies to Wire v1 and Wire v2 sessions alike (`spec/wire-v2.md` Section 5.1).

| Code | Name | Sent by | Refusal |
|---|---|---|---|
| `1000` | `normal` | either | no |
| `1002` | `protocol_error` | either | no |
| `1008` | `policy_violation` | either | no |
| `1011` | `internal_error` | responder | no |
| `4001` | `peer_revoked` | responder only | yes (`Revoked`) |
| `4002` | `grant_expired` | either | no (reserved) |
| `4003` | `key_unverified` | either | no (reserved) |
| `4004` | `peer_pending` | responder only | yes (`Pending`) |
| `4400..=4499` | admission refusals | responder only | yes (`Other(code)`), reserved for future use |

- A **refusal** is a `0x07 CLOSE` whose code is marked "yes" above. It tells a known initiator that the host has authenticated it and will not admit it.
- A responder MUST send refusal codes with empty reason text (`payload.len() == 2`).
- Only an **initiator** maps a received refusal code to a refusal reason. A responder that receives a refusal code keeps the raw code and text as a plain close and never maps it to a refusal.
- Every other code keeps its plain close meaning. `4002` and `4003` are never refusals. A code outside this registry is a plain close.
- A refused Wire v1 session is exactly `uint16_be(19) || AEAD(0x07 || code_be16)`: one 21-byte outer frame, the first transport frame the responder writes.
- An initiator reports `Established` when it writes `msg3` (Section 3.3) and MUST NOT wait for a post-`msg3` frame before doing so: a healthy responder sends nothing until it has traffic. A refusal that arrives after `Established` is surfaced as a session close carrying the code, and later operations on the session fail with that code.

#### 5.4.2 Refusal Limiter

A responder keeps one refusal limiter per endpoint, shared by its Wire v1 and Wire v2 responders. It allows at most one refusal per peer `device_id` per `10 s` and tracks at most `256` peers (least recently used first out). When the limiter denies a refusal, the responder falls back to the silent behaviour of the same row (Section 3.3 step 3, `spec/wire-v2.md` Section 3.1.3): Wire v1 drops with 0 bytes, Wire v2 sends the decoy. A refusal audit record, when the embedder keeps one, is emitted only when the limiter allowed the refusal, so a flood of attempts cannot evict other audit records.

#### 5.4.3 Refusal-Enabled Listeners

Whether a listener may refuse is a property of the accept path, never of roster contents:

| Accept path | Refusals |
|---|---|
| An ordinary session listener (Wire v1 or Wire v2) | enabled |
| A dispatcher that also admits ordinary sessions on an endpoint with groups open | enabled only for candidates from the persisted ordinary roster. Group sibling pins (manifest-pinned entries) and group rendezvous secrets are silent |
| A group listener, group pool or group mailbox | never; a refusal would link the group endpoint to the host |

#### 5.4.4 Refusal Close Sequence

After writing the refusal frame, a Wire v1 responder:

1. Releases the half-open handshake slot that the connection held, so refused peers cannot block admission of `active` peers.
2. Half-closes its write side where the transport supports it (for example TCP or Unix stream shutdown), so unread inbound bytes do not turn the close into a reset that discards the frame. Message-framed transports (WebSocket, relay, QUIC) close normally.
3. Reads and discards inbound bytes until end of stream or `250 ms` (`REFUSAL_LINGER`), then closes. An implementation MAY bound the number of connections lingering at once (the reference runtime uses `8`) and close immediately when the bound is reached.
4. Reports the refusal to the embedder as a failed accept (`PeerRevoked` or `PeerPending`) and continues accepting.

The same sequence applies to a Wire v2 responder that refuses at `msg3` time (`spec/wire-v2.md` Section 3.1.4). A Wire v2 refusal at `msg2` does not use it: that responder keeps the decoy path timing (`spec/wire-v2.md` Section 3.1.3.3).

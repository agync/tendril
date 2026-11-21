# Tendril Wire Specification v2

Status: **Normative (v2)**

Conventions: `b64url` means unpadded URL-safe base64 (RFC 4648 Section 5, no `=`). `hex` means lowercase hexadecimal unless stated otherwise. All integers on the wire are big-endian (`be`). The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `MAY` are interpreted per RFC 2119.

This specification defines the Tendril v2 Privacy Profile (`WIRE_VERSION_V2 = 0x02`). Wire v1 (`0x01`, `spec/wire-v1.md`) remains frozen and intact for backward compatibility with unupgraded peers.

---

## 1. Cipher Suite, Versioning, and Anti-Downgrade

- Noise pattern (fixed): `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` (`fips203` ML-KEM-768 + X25519 + ChaCha20-Poly1305 + SHA-256).
- Identity signing suite (fixed): Hybrid `Ed25519 (32 B pub / 64 B sig) || ML-DSA-65 (1952 B pub / 3309 B sig)` = `1984`-byte public keys (`SHA-256` pin `32` bytes) and `3373`-byte signatures with ML-DSA-65 context `"tendril-hybrid-v1"`.
- Wire version: `0x02`.
- Outer transport security (TLS, WireGuard, peer-to-peer stream encryption, WSS) is treated as untrusted byte plumbing. Only the inner Noise session authenticates peers and carries authorization.

### 1.1 Anti-Downgrade Invariant (`min_wire_version`)

- Every persisted peer or pinned host record carries `min_wire_version: u8` (validated to `{1, 2}` on deserialization, defaulting to `1` for legacy v1 records).
- Immediately upon recording a peer over `0x02` (`Pending` or `Active`), or when an operator sets `min_wire_version = 2`, the endpoint MUST persist `min_wire_version >= 2` for that peer.
- Decreasing `min_wire_version` below an existing persisted floor MUST be rejected unless the peer entry is explicitly revoked and re-paired out of band.
- If a peer or pinned host has `min_wire_version >= 2`, both initiators and responders MUST fail closed (`VersionDowngrade`) before disclosing `SessionHello`, `PairClaim`, or application data, and before burning any pairing code or enrollment nonce, whenever a connection attempts to negotiate `0x01`.
- Before initiating v1 pairing against a host, initiator embedders/drivers MUST pass the persisted peer floor (via `Roster::pairing_floor` or `V2PinnedHost`) into `PairingInitiator::new_with_min_wire_version` / `PairingInitiator::new_m2m_with_min_wire_version` so v1 pairing aborts immediately if `min_wire_version >= 2`.
- When initiating an unpinned v1 pairing session, drivers MUST also pass `.with_roster_floors(&roster)` on `PairingInitiator` so that if `HostHello` (`msg2`) matches any persisted peer with `min_wire_version >= 2` (by `static_pub` or `host_id`), the initiator aborts with `VersionDowngrade` before computing `code_mac` or sending `PairClaim` (`msg3`).

---

## 2. Cleartext Preamble and Outer Framing

### 2.1 Preamble (6 bytes, client to server)

Every v2 connection opens with exactly 6 raw bytes sent by the initiator before the first framed message:

```text
offset  bytes  field    value
0       3      magic    ASCII "TND" (0x54 0x4E 0x44)
3       1      version  0x02
4       1      intent   0x01 = session
                        0x02 = pair
5       1      flags    0x00 = standard v2
                        0x01 = FLAG_PAKE_PAIR (allowed ONLY when intent == 0x02)
```

- Responders MUST close the connection immediately (and charge pre-auth rate limits) if `magic != "TND"`, `version` is unsupported, `intent` is not `0x01` or `0x02`, `intent == 0x01 && flags != 0x00`, or `intent == 0x02 && flags` is not `0x00` or `0x01`.
- For standard v2 (`flags == 0x00`), the exact 6 preamble bytes are fed verbatim as the Noise **prologue** on both sides before processing `msg1`.
- For PAKE pairing (`intent == 0x02`, `flags == 0x01`), the Noise prologue is the 38-byte concatenation `preamble (6 B) || pake_context_tag (32 B)` defined in Section 3.2.
- Mutating any preamble byte causes AEAD decryption failure in `msg2` and `msg3`.

### 2.2 Length-Prefixed Framing (both directions, post-preamble)

All bytes after the 6-byte preamble use the same length-prefixed framing as v1:

```text
frame = uint16_be len || body (len bytes)
```

- `len` MUST satisfy `0 <= len <= 65519` (`0xFFEF`).
- Receivers MUST inspect `len` and reject `len > 65519` before allocating a frame buffer.
- Transport readers MUST support resumable partial-frame reads across I/O deadlines.

---

## 3. Noise XXhfs Handshake Modes in v2

### 3.1 Pseudonymous Paired Reconnect (`intent = 0x01`, `flags = 0x00`)

In v1 `Noise_XXhfs`, `msg2` is encrypted only under ephemeral `ee + ekem1`, allowing active scanners to read `HostHello` (`host_id`, `signing_pub`, `rotation`) and the responder's static X25519 key. In v2 paired reconnect, the initiator proves knowledge of a shared 32-byte `reconnect_secret` in `msg1`, and the responder hides both its real static key (on failed probes) and `HostHello` inside a constant-bucket encrypted envelope.

#### 3.1.1 Secret Export and Storage

Upon completing any v2 `Noise_XXhfs` handshake (pairing or session), both sides hold the post-`se` chaining key `ck` (32 B) and final handshake hash `h` (32 B) prior to `Split()`:

```text
exporter_secret  = HKDF-SHA256(ikm = ck, salt = h, info = "tendril-v2-session-export")
reconnect_secret = HKDF-SHA256(ikm = exporter_secret, salt = "tendril-reconnect-v2", info = host_static_pub)
mailbox_secret   = HKDF-SHA256(ikm = exporter_secret, salt = "tendril-mailbox-v2",   info = host_static_pub)
```

- Pairing-derived `mailbox_secret` and `reconnect_secret` MUST be persisted in an encrypted-at-rest keystore (OS Keychain / Keystore / sealed roster store) and zeroized on drop. They MUST NOT appear in debug or audit logs.
- Pairing-derived `reconnect_secret` and `mailbox_secret` are retained across reconnects (preventing `msg3`-drop or concurrent-session secret desynchronization); session-exported secrets are informational/explicit-only and MUST NOT overwrite persisted pairing-derived secrets on normal reconnects.
- On reconnect, reaching `Established` (`msg3` verified against an `Active` peer) raises `min_wire_version = 2` for that peer; responders MUST NOT mutate persisted peer state speculatively when emitting `msg2`.

#### 3.1.2 `msg1` Timestamped Rendezvous Proof (56 bytes)

The initiator generates a fresh 16-byte CSPRNG `rendezvous_nonce`, records its current Unix timestamp `ts_unix` (`8 B` big-endian `uint64`), computes the SHA-256 digest of its ML-KEM-768 encapsulation key `ekem_i_hash = SHA-256(e1)`, and places the 56-byte proof into `msg1` payload:

```text
rendezvous_mac = HMAC-SHA256(
    key = reconnect_secret,
    msg = "tendril-v2-rendezvous\0" (22 B)
       || preamble (6 B)
       || e_i_pub (32 B)
       || ekem_i_hash (32 B)
       || rendezvous_nonce (16 B)
       || ts_be8 (8 B)
)

msg1_payload = rendezvous_nonce (16 B) || ts_be8 (8 B) || rendezvous_mac (32 B)
```

Total `msg1` body size is `1216 + 56 = 1272` bytes.

#### 3.1.3 Responder Rendezvous Verification and Indistinguishable Decoy `msg2`

Upon receiving `msg1`, the responder:

1. Checks `|ts_unix - now_unix| <= 300` seconds and checks `RendezvousReplayCache` for `rendezvous_nonce` and spare live capacity. Multi-connection listeners MUST share a single `RendezvousReplayCache` instance across concurrent inbound connections; at capacity (`MAX_RENDEZVOUS_REPLAY_ENTRIES`), the cache MUST evict only expired entries (`now_unix > ts_unix + 300`) and fail closed (route to decoy) rather than evicting live entries.
2. Evaluates `rendezvous_mac` across all roster entries in constant time (executing a dummy HMAC for non-active or v1-only entries) without early exit, even if `payload.len() != 56`.
3. Computes the target handshake bucket `bucket` from `V2_HANDSHAKE_BUCKETS = [4096, 16384, 32768, 63488]` matching `2 + len(host_hello_json) + 16` for the responder's actual `HostHello` (including any active `rotation` chain).

- **When verified, fresh (`<= 300s` skew), and un-replayed (with cache capacity):**
  1. Record `(rendezvous_nonce, ts_unix)` in `RendezvousReplayCache`.
  2. Build `Noise_XXhfs` with the responder's real static X25519 private key and process `msg1`.
  3. Construct `HostHello` (`proto_version = 2`), pad `uint16_be(len) || host_hello_json || 0x00...` to `bucket - 16`, derive `hello_seal_key = HKDF-SHA256(ikm = reconnect_secret, salt = rendezvous_nonce, info = "tendril-v2-hello-seal")`, and encrypt with `ChaCha20Poly1305(key = hello_seal_key, nonce = 0x00^12, aad = h_pre)` right before encrypting `msg2` payload (where `h_pre` is the Noise handshake hash immediately prior to `msg2` payload encryption).
- **When missing, malformed, stale (`> 300s` clock skew), replayed, or invalid (unauthenticated probe):**
  1. Unconditionally generate a fresh ephemeral X25519 decoy keypair (`decoy_static`) so the active probe learns neither `static_pub` nor `device_id`. (When an authentic peer has `> 300s` clock skew, the responder routes to decoy and the initiator surfaces `HostKeyUnverified` upon decrypting or failing to unseal `HostHello`.)
  2. Build `Noise_XXhfs` with `decoy_static`, process `msg1`, and emit `bucket` bytes of fresh CSPRNG data as the `msg2` payload (exact same wire byte length as a genuine `msg2`, even when the host has rotated).
  3. Upon receiving `msg3`, reject the connection unconditionally (`HostKeyUnverified`).

#### 3.1.4 Initiator Verification at `msg2` and Padded `msg3`

Before transmitting `msg3`, the initiator:

1. Decrypts `msg2` with `Noise_XXhfs`, recording `h_pre` immediately prior to payload decryption.
2. Derives `hello_seal_key` from `reconnect_secret` and `rendezvous_nonce`, decrypts `sealed_envelope` (`nonce = 0x00^12`, `aad = h_pre`), verifies trailing zero padding in constant time, and parses `HostHello`.
3. Verifies `proto_version == 2`, `host_id == target_host_id`, `signing_pub`, `remote_static`, and any `rotation` chain against the stored `Roster` pin. If verification fails, the initiator aborts immediately without writing `msg3`.
4. Encodes `SessionHello` into a padded `msg3` payload (`uint16_be(len) || session_hello_json || 0x00...`) rounded up to the smallest bucket in `[512, 1024, 2048, 4096, 8192, 16384, 32768, 63488]`.

On `msg3`, the responder MUST verify that `peer_static` matches the exact `RosterEntry` whose `reconnect_secret` authenticated `msg1`, enforce `PeerState::Active`, CRLs, `SessionHello.device_id == device_id(peer_static)`, and any presented `Grant`.

---

### 3.2 Hybrid PAKE + ML-KEM-768 Pairing (`intent = 0x02`, `flags = 0x01`)

Classic v1 pairing sends `HostHello` in `msg2` before `code_mac` is verified in `msg3`. In v2 PAKE pairing mode, the normalized human pairing code is bound into `msg1` MAC, the Noise prologue, and `HostHello` sealing, hiding `HostHello` and the responder's static key from unauthenticated probers.

#### 3.2.1 Argon2id + HKDF Key Schedule

The initiator generates a fresh 16-byte CSPRNG `channel_salt` and normalizes the pairing code per `spec/pairing-v1.md` Section 3.2 (ASCII uppercase, strip `-`):

```text
master_pake = argon2id(
    password = UTF-8(code_normalized),
    salt     = channel_salt (16 B),
    t        = 2,
    m        = 19456,    // 19 MiB in KiB (enforced minimum in production builds)
    p        = 1,
    keyLen   = 32,
    version  = 0x13      // Argon2 v1.3
)

pake_prologue_key = HKDF-SHA256(ikm = master_pake, salt = channel_salt, info = "tendril-v2-pake-prologue")
pake_init_key     = HKDF-SHA256(ikm = master_pake, salt = channel_salt, info = "tendril-v2-pake-init-key")
pake_hello_key    = HKDF-SHA256(ikm = master_pake, salt = channel_salt, info = "tendril-v2-pake-hello")
pake_confirm_key  = HKDF-SHA256(ikm = master_pake, salt = channel_salt, info = "tendril-v2-pake-confirm")
pake_context_tag  = HKDF-SHA256(ikm = pake_prologue_key, salt = channel_salt, info = "tendril-v2-pake-context")
```

**Offline Dictionary Resistance Note:** Because a legitimate `msg1` carries `init_mac` and a legitimate `msg2` carries `resp_confirm_mac`, a passive observer of a legitimate `msg1+msg2` exchange can test pairing code guesses offline at the cost of one `Argon2id(19 MiB, t=2, p=1)` evaluation per guess. For `Remote3Group` (`31^12 ~= 2^59.4` codes), offline brute force is infeasible; for shorter `Lan2Group` (`31^8 ~= 2^39.6` codes), deployments MUST restrict `Lan2Group` codes strictly to trusted local networks and SHOULD use `Remote3Group` on untrusted networks. Runtime embedders MUST bound concurrent Argon2id derivations to prevent memory/CPU DoS.

#### 3.2.2 Handshake Binding

1. **Prologue:** Validated handshakes initialize `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` with the 38-byte prologue `preamble (6 B) || pake_context_tag (32 B)`.
2. **`msg1` (Initiator -> Responder, 48-byte payload):** Carries `channel_salt (16 B) || init_mac (32 B)` (`msg1` total = `1216 + 48 = 1264` bytes), where:
   - `init_mac = HMAC-SHA256(pake_init_key, "tendril-v2-pake-msg1\0" || preamble (6 B) || e_i_pub (32 B) || SHA-256(e1) (32 B) || channel_salt (16 B))`.
3. **`msg2` (Responder -> Initiator):** Responder extracts `channel_salt` and `init_mac`, checks its bounded `(channel_salt, init_mac)` replay cache, and computes target bucket `bucket` from `V2_HANDSHAKE_BUCKETS = [4096, 16384, 32768, 63488]` for `2 + len(host_hello_json) + 16 + 32`:
   - Responder evaluates `init_mac` in constant time across all live codes without early return, and pads `Argon2id` work on `msg1` up to at least `V2_PAKE_FIXED_ARGON2_PASSES` (`4`) passes using fresh 32-byte CSPRNG dummy secrets and `channel_salt` so response timing does not leak the number of open pairing codes (`0`, `1`, `2`, `3`).
   - **If no live code matched `init_mac`, or `(channel_salt, init_mac)` was already replayed, or the replay cache is full:** Responder builds `Noise_XXhfs` with a fresh ephemeral decoy X25519 static keypair and fresh 32-byte CSPRNG `decoy_tag` prologue, emits `bucket` bytes of CSPRNG decoy `msg2` payload (same `V2_HANDSHAKE_BUCKETS` length as a real PAKE `HostHello` `msg2` including the `32`-byte `resp_confirm_mac` overhead), does NOT charge any live pairing code, and rejects `msg3` (`PairingAuthFailed`).
   - **If a live code matched `init_mac` and `(channel_salt, init_mac)` is recorded in the bounded replay cache:** Responder builds `Noise_XXhfs` with its real static key and `preamble || pake_context_tag` prologue, reads `msg1`, and right before encrypting `msg2` payload reads `h_pre`:
     - `sealed_host_hello = ChaCha20Poly1305(key = pake_hello_key, nonce = 0x00^12, aad = h_pre, pt = host_hello_json)` (`proto_version == 2`).
     - `resp_confirm_mac = HMAC-SHA256(pake_confirm_key, "tendril-v2-pake-resp\0" || h_pre || sealed_host_hello)` (`32` B).
     - `msg2` payload = `uint16_be(len(sealed_host_hello)) || sealed_host_hello || resp_confirm_mac (32 B) || 0x00...` padded to `bucket`.
   Initiator verifies Noise AEAD, constant-time zero padding, and `resp_confirm_mac`, unseals `HostHello`, verifies `proto_version == 2` and any `PinnedHost`, and computes `pairing_sas(post_msg2_hash)`. On any failure, initiator aborts with `PairingAuthFailed` before emitting `msg3`.
4. **`msg3` (Initiator -> Responder):** Initiator encodes `PairClaim` JSON (`code_mac` omitted) and computes:
   - `init_confirm_mac = HMAC-SHA256(pake_confirm_key, "tendril-v2-pake-init\0" || post_msg2_hash || claim_json)` (`32` B).
   - `msg3` payload = `init_confirm_mac (32 B) || claim_json`.
   Responder verifies Noise AEAD and `init_confirm_mac` in constant time, rejecting invalid `msg3` (`PairingAuthFailed`) without charging or burning live pairing codes (replaying a captured `msg1` hits the `(channel_salt, init_mac)` replay cache and is routed to the decoy path).
5. **Completion:** Responder burns the matched pairing code, records the peer in `Pending` state with `min_wire_version = 2` and exported `(reconnect_secret, mailbox_secret)` persisted immediately, and sends the encrypted `PairResponse` over transport mode before closing.

---

## 4. Signed Key Rotation (`RotationRecord`)

`RotationRecord` format, exact 4031-byte binary signing input (`"tendril-rot-v1\0"`), and fork-detection rules are identical to `spec/wire-v1.md` Section 4.

---

## 5. Bucketed Inner Transport Envelope and Cover Traffic

Inside Noise transport mode, each outer AEAD frame decrypts to a plaintext payload of `1..=65503` bytes (`MAX_TRANSPORT_PLAINTEXT = 65503`).

### 5.1 Inner Frame Types

| `frame_type` | Name | Availability | Payload Layout | Semantics |
|---|---|---|---|---|
| `0x01`..`0x07` | v1 types | v1 and optional v2 rx | See `spec/wire-v1.md` Section 5 | Legacy unpadded frames |
| `0x08` | `PADDING` | v2 only | `0..(MAX_TRANSPORT_PLAINTEXT - 1)` zero bytes (`0x00`) | Pure cover traffic; silently discarded after AEAD decrypt and nonce advance |
| `0x09` | `PADDED` | v2 only | `inner_type (1 B) || real_len (2 B uint16_be) || real_payload || zero_padding` | Length-hidden envelope enclosing one inner frame of type `0x01..=0x03`, `0x05..=0x07`, or `0x04` via `seal_rekey()` |

Receivers MUST reject `0x08` and `0x09` on v1 (`0x01`) sessions (`UnknownInnerFrameType`). Direct application `seal()` calls MUST reject `0x04 REKEY`, `0x08 PADDING`, and `0x09 PADDED` (callers use `seal_rekey()` and `seal_dummy_cover()`).

### 5.2 Standard Padding Buckets and Validation

Standard bucket sizes for total inner plaintext length (before adding the 16-byte ChaCha20-Poly1305 AEAD tag):

```text
[256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65503]
```

- When sealing an inner frame of type `kind in 0x01..=0x07` with `real_payload`:
  - `real_payload.len()` MUST satisfy `real_payload.len() <= 65499` (`MAX_TRANSPORT_PLAINTEXT - 4`). Oversized or invalid payloads MUST fail closed BEFORE advancing the TX cipher state, calling `seal_rekey()`, or incrementing TX nonces.
  - Select the smallest bucket `B >= 4 + real_payload.len()`.
  - Emit `0x09 || (kind as u8) || uint16_be(real_payload.len()) || real_payload || 0x00^(B - 4 - real_payload.len())`.
- When receiving `0x09` `PADDED`:
  - Require `plaintext.len() >= 4`.
  - Require `inner_type` is in `0x01..=0x07` (nested `0x08` or `0x09` MUST be rejected).
  - Require `real_len <= plaintext.len() - 4`.
  - Verify every trailing padding byte in `plaintext[4 + real_len..]` equals `0x00` in constant time (`subtle::ConstantTimeEq`); reject any non-zero padding byte (`InvalidInnerFramePayload`).
  - Validate per-type inner payload rules (e.g., `REKEY` empty, `PING`/`PONG` 8 bytes, `CLOSE >= 2` bytes).
- When receiving `0x08` `PADDING` (dummy cover frame):
  - Verify every byte in `plaintext[1..]` equals `0x00` in constant time; reject any non-zero byte.
  - Advance the Noise RX nonce as normal for AEAD decryption and discard the frame without emitting application data.

---

## 6. Jittered Keepalive and Rekey Scheduling

To prevent periodic traffic-analysis fingerprints on idle or long-lived flows, v2 sessions replace fixed intervals with CSPRNG-jittered schedules (`ScheduleJitterPolicy`):

- **Keepalive `PING` delay:** Given base `ping_interval_ms` and `ping_jitter_bps` (default `2500` = `+-25%`, `<= 10000`), sample each interval uniformly via unbiased CSPRNG in `[ping_interval_ms - delta, ping_interval_ms + delta]` (clamped to `>= 1` ms).
- **Per-epoch `REKEY` thresholds:** At session start and after each `0x04 REKEY`, sample fresh `RekeyThresholds` uniformly via unbiased CSPRNG inside `[75%..=100%]` of `(rekey_max_frames, rekey_max_age_secs * 1000)` (defaults: `rekey_max_frames = 1_048_576`, `rekey_max_age_secs = 900`, `rekey_min_pct_bps = 7500`; hard safety ceilings: `max_frames <= 2^32` and `max_age_ms <= 7 days`).
- Implementations MUST pre-validate outgoing frames and sample the next epoch's `RekeyThresholds` BEFORE mutating TX cipher keys when triggering `0x04 REKEY`, and MUST re-verify peer status, CRLs, and active grants immediately after incoming `0x04 REKEY` or `0x03 REVOCATION`.

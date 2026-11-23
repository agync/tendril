---
type: Design
title: Wire protocol and pairing
description: Preamble framing, Noise XXhfs hybrid PQ handshake, transcript-bound pairing proof, hybrid key rotation chains, and inner encrypted transport frames.
status: stable
tags: [design, wire, pairing]
---

# Wire protocol and pairing

Every Tendril connection establishes a hybrid post-quantum `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` channel before application data or pairing claims move. The outer transport layer is treated as an untrusted byte pipe.

## Framing and prologue

1. Initiator sends a 6-byte cleartext preamble: ASCII `"TND"` (`0x54 0x4E 0x44`), version `0x01`, intent (`0x01` session or `0x02` pair), and reserved byte `0x00`.
2. Both peers feed those exact 6 bytes verbatim as the Noise prologue, preventing cross-intent splicing or downgrade.
3. Every subsequent outer frame is length-prefixed as `uint16_be len || body`, where `0 <= len <= 65519` (`0xFFEF`). Receivers reject oversized lengths before allocation and preserve partial-frame reads across deadlines; senders check the encrypted frame limit before advancing AEAD nonces.

## Pairing ceremony

```mermaid
sequenceDiagram
  participant D as Initiator (Device)
  participant H as Responder (Host)
  Note over H: Host shows pairing code and host_fingerprint
  D->>H: Preamble (intent = pair) + Noise msg1 (e, e1) [1216 B]
  H->>D: Noise msg2 (e, ee, ekem1, s, es) + HostHello (signing_pub)
  Note over D: Verify HostHello.signing_pub against sh= hash or full pin before msg3; derive h
  Note over D,H: Both compute pairing_sas from SHA-256("tendril-sas-v1" || h)
  D->>H: Noise msg3 (s, se) + PairClaim (code_mac over h, signing_pub + key proof)
  H->>D: Encrypted PairResponse (pending) and close
  Note over H: Human compares device_fingerprint + pairing_sas, then runs pair.confirm and pair.mint
```

| Identifier or Proof | Construction | Format or Bound |
|---|---|---|
| `device_id` | `"dev_" + hex_lower(SHA-256(static_pub)[..8])` | 20 ASCII chars |
| `host_fingerprint` | `group4(first16(lower(base32_nopad(SHA-256(static_pub)))))` | `xxxx xxxx xxxx xxxx` |
| `device_fingerprint` | `group4(first16(upper(hex(SHA-256(static_pub)))))` | `XXXX XXXX XXXX XXXX` |
| `pairing_sas` | `group4(first16(lower(base32_nopad(SHA-256("tendril-sas-v1" \|\| h)))))` | `xxxx xxxx xxxx xxxx` |
| `code_mac` | `HMAC-SHA256(argon2id(code_norm, h[..16], t=3, m=65536, p=1, v=0x13), "tendril-pair-v1" \|\| h)` | 32 bytes (`b64url`) |
| Key proof (`enroll_proof`) | Hybrid signature by `signing_pub` over `"tendril-pair-key-v1\0" \|\| h \|\| initiator static_pub` | 3373 bytes (`b64url`) |

Codes default to a 15-minute TTL, are capped at `MAX_LIVE_PAIRING_CODES = 4` concurrent live codes (`CoreError::ProtocolViolation` when `>= 4` unexpired codes exist), and burn after 5 failed claim attempts across live codes. Manual pairing requires explicit SAS confirmation before leaving `pending` state unless an operator opts in via fingerprint-only confirmation. The human `PairClaim` also carries the initiator's hybrid `signing_pub` with a key proof bound to `h` and its static key, verified after the code burns, so the host pins the key it needs for groups (`spec/pairing-v1.md` Section 4.1). Peers paired before that change have no pinned key: a re-pair records it and returns an `active` entry to `pending` until the operator confirms the new SAS. A claim with a different key than one pinned for the same static key, under any label, is refused; signing keys change only through rotation. A keyless claim cannot replace the SAS of a `pending` entry that holds an unconfirmed key. A Wire v1 responder built before the change rejects a keyed claim as `protocol_error`. For opt-in headless deployment without interactive SAS, `PairClaim` carries `enrollment_token`, `signing_pub`, and `enroll_proof` instead of `code_mac`, requires an out-of-band host pin (`PinnedHost`), burns the token nonce atomically, and transitions directly to `"active"` with zero application grants; see [Machine-to-machine enrollment](m2m-enrollment.md).

## Inner encrypted frames and rotation

Inside `intent = session`, decrypted Noise transport frames (`<= 65503` bytes) carry a 1-byte `frame_type` prefix (`0x01 DATA`, `0x02 GRANT`, `0x03 REVOCATION`, `0x04 REKEY`, `0x05 PING`, `0x06 PONG`, `0x07 CLOSE`). Peers trigger `0x04 REKEY` automatically after `1_048_576` frames or 15 minutes and re-evaluate active grants against the latest revocation list.

Key rotations carry a strictly monotonic `seq` counter and a `3373`-byte hybrid `Ed25519 || ML-DSA-65` signature (`ctx = "tendril-hybrid-v1"`) over the `4031`-byte payload (`"tendril-rot-v1\0" || seq_be8 || prev_signing_pub (1984 B) || new_signing_pub (1984 B) || new_static_pub (32 B) || ts_be8`). Any conflicting valid record at the same `seq` moves the peer entry immediately to `revoked`.

## Group frames

Two further inner frame types serve small peer mesh groups: `0x0A GROUP_MANIFEST` (a compact signed manifest, at most `32768` bytes) and `0x0B GROUP_RENDEZVOUS` (exactly `60` bytes: `group_id`, `seq`, and the 32-byte rendezvous key). A receiver closes the session on a `0x0A` above `32768` bytes or a `0x0B` of any other length. The initiator's optional `SessionHello.groups` lists `{group_id, seq}` gossip for the one group it is dialing (at most `16` entries, omitted when empty), which lets a responder holding a newer manifest queue it as `0x0A`. Core never ingests these frames on its own: the runtime hands them to `GroupBook`, which verifies and authorizes them. See [Small peer mesh groups](groups.md) and `spec/groups-v1.md`.

Normative byte rules live in `spec/wire-v1.md`, `spec/pairing-v1.md`, and `spec/groups-v1.md`.

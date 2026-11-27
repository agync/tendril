---
type: Design
title: Wire protocol and pairing
description: Preamble framing, Noise XXhfs hybrid PQ handshake, transcript-bound pairing proof, signed multi-route pairing URIs, refusal close codes for revoked and pending peers, hybrid key rotation chains, and inner encrypted transport frames including signed route announcements.
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

## Pairing URIs, route statements and multi-rung pairing

A host shows one `tendril://pair?...` URI. Besides the pins (`k`, `sh`, optional `id` and `seq`), it carries the fields that make one QR code work across several paths (`spec/pairing-v1.md` Section 6):

| Field | Form | Rule |
|---|---|---|
| `ep` | Comma-separated hints, at most `6`, each at most `256` bytes | Dialing hints only. Never `local:` or `unix://` from a URI. No `#`. |
| `rp` | 43-character base64url Ed25519 key | Selects the host's `/v1/relay` mailbox. Required with a `/v1/relay` hint, forbidden without one, and checked equal to the Ed25519 half of the authenticated `HostHello.signing_pub` before `msg3`. Never persisted. |
| `rq` | Decimal route sequence, `1..=2^53-1` | Present exactly when `rs` is, immediately before it. |
| `rs` | 86-character base64url Ed25519 signature | Always last. Signs `"tendril-pairing-routes-v1\0" || uri_bytes_before_rs` with the Ed25519 half of the host identity key, so it covers every other parameter byte for byte. |

A URI is at most `1,024` bytes. A builder aims for `711` bytes (QR Version 21, ECC M) and reports its length without trimming to meet the target. The URI parser rejects a URI that mixes a `Lan2Group` code with a remote-class hint, because the responder burns a two-group code claimed over a remote path.

**Order of checks.** An initiator races the URI's hints (Wire v1) or tries them one at a time (Wire v2, so each rung receives its own offline-testable proof). For each candidate it verifies `msg2` and the `HostHello` against the pin, then `rp`, then `rs`, and only then builds `msg3`. An invalid `rs` aborts the attempt before any claim bytes exist and leaves the code live. A statement whose `sh` no longer matches the host's current key (the host rotated after issuing the URI) is reported as `route_key_rotated` and authorizes nothing.

**Commit boundary.** An attempt becomes irrevocable immediately before the first write that carries any `msg3` byte. After that point every outcome ends the attempt: no other rung is dialed, no `msg3` is rebuilt, and nothing is persisted on the client. A result marked `committed` tells the caller the code may be spent and the recovery is a new code.

**What a pairing stores.** Persistence follows the client's route policy (`allSigned` by default). Only a statement that verified under the host's authenticated key, and whose signed code equals the code used, yields `signed` routes. A merge never lowers the stored route sequence. See [Seamless pairing defaults](../usage/seamless-pairing.md) for the policy table.

## Signed route announcements (`0x0C`)

A host keeps its paired clients' `signed` routes current inside the session. Its route set is one statement: the host's static key, `sh`, a persistent sequence, an issue time and up to six hints.

| Item | Rule |
|---|---|
| Payload | `route_set_body || sig`, `3455..=5003` bytes. The body is `82..=1630` bytes: version, static key, `sh`, `seq`, `issued_at`, count, then length-prefixed hints. |
| Signature | `3373`-byte hybrid `Ed25519 || ML-DSA-65` over `"tendril-route-set-v1\0" || body`. Both halves must verify. |
| Direction | Responder to initiator only. A responder that receives `0x0C` closes the session. |
| Opt-in | Sent only to an initiator whose `SessionHello` carried `route_seq`. Other clients never see the frame. |
| Wire v2 | Valid only inside `0x09 PADDED`. A session with padding disabled neither sends nor receives it. |
| Client acceptance | Entry active and not revoked, keys match the pin, signature verifies, `issued_at` at most 24 hours ahead, and `seq` newer than the stored one (or equal over a route set that came from a URI). A rejection is recorded and never closes the session. |

The host's sequence lives in its roster, so it survives restarts and only moves when the advertised set changes. Structural failures close the session; semantic ones never do. See `spec/wire-v1.md` Section 5.2 for the exact bytes and the receive pipeline.

## Refusing revoked and pending peers

A host can tell a known device that it is revoked or still waiting for `pair.confirm`, so the device stops guessing between a dead host and a blocked key. On Wire v1 the host learns who the device is only from `msg3`. It then checks the entry's wire floor first, so a v2-floored entry still gets `VersionDowngrade` and no bytes. Otherwise it finishes the handshake and sends one encrypted `0x07 CLOSE` with `4001 peer_revoked` or `4004 peer_pending` and empty text. It then releases the half-open slot, half-closes the stream so the frame is not lost to a reset, drains for at most `250 ms`, and closes (`spec/wire-v1.md` Sections 3.3 and 5.4). Wire v2 refuses earlier, at `msg2`, with a sealed refusal (see [Wire v2 privacy profile and PAKE](wire-v2-privacy.md)).

| Close code | Meaning | Refusal |
|---|---|---|
| `1000`, `1002`, `1008`, `1011` | normal, protocol error, policy violation, internal error | no |
| `4001` | `peer_revoked`: the host blocks this device key permanently | yes |
| `4002`, `4003` | `grant_expired`, `key_unverified` (reserved) | no |
| `4004` | `peer_pending`: the host has not confirmed this device yet | yes |
| `4400..=4499` | reserved admission refusals | yes |

- **Who is told:** revocations record a notice by default, kept for 30 days. An operator can revoke with `notify: false`, set the lifetime to `0`, or clear one notice while the key stays revoked. Fork revocations are always silent. Pending notices are on by default.
- **Who is not told:** a stranger gets the same drop as before, with no `CLOSE`. Group listeners never refuse. A limiter allows one refusal per peer per `10 s` and falls back to silence.
- **Revocation stays permanent:** a host never re-admits a revoked key. A refused device that wants back in re-pairs with a fresh identity (`spec/pairing-v1.md` Sections 5.1 and 5.2).
- **Privacy residual on Wire v1:** a passive observer can see one extra 21-byte frame after `msg3` and so tell a refusal from a silent drop. Wire v1 is not the privacy profile; v2-floored entries never send it.

Only an initiator reads a refusal code as a refusal. A responder that receives one keeps it as a plain close.

## Inner encrypted frames and rotation

Inside `intent = session`, decrypted Noise transport frames (`<= 65503` bytes) carry a 1-byte `frame_type` prefix (`0x01 DATA`, `0x02 GRANT`, `0x03 REVOCATION`, `0x04 REKEY`, `0x05 PING`, `0x06 PONG`, `0x07 CLOSE`, plus `0x0C ROUTE_SET` below). Peers trigger `0x04 REKEY` automatically after `1_048_576` frames or 15 minutes and re-evaluate active grants against the latest revocation list.

Key rotations carry a strictly monotonic `seq` counter and a `3373`-byte hybrid `Ed25519 || ML-DSA-65` signature (`ctx = "tendril-hybrid-v1"`) over the `4031`-byte payload (`"tendril-rot-v1\0" || seq_be8 || prev_signing_pub (1984 B) || new_signing_pub (1984 B) || new_static_pub (32 B) || ts_be8`). Any conflicting valid record at the same `seq` moves the peer entry immediately to `revoked`.

## Group frames

Two further inner frame types serve small peer mesh groups: `0x0A GROUP_MANIFEST` (a compact signed manifest, at most `32768` bytes) and `0x0B GROUP_RENDEZVOUS` (exactly `60` bytes: `group_id`, `seq`, and the 32-byte rendezvous key). A receiver closes the session on a `0x0A` above `32768` bytes or a `0x0B` of any other length. The initiator's optional `SessionHello.groups` lists `{group_id, seq}` gossip for the one group it is dialing (at most `16` entries, omitted when empty), which lets a responder holding a newer manifest queue it as `0x0A`. Core never ingests these frames on its own: the runtime hands them to `GroupBook`, which verifies and authorizes them. See [Small peer mesh groups](groups.md) and `spec/groups-v1.md`.

Normative byte rules live in `spec/wire-v1.md`, `spec/pairing-v1.md`, and `spec/groups-v1.md`.

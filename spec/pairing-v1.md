# Tendril Pairing Specification v1

Status: **Normative (v1)**

Conventions follow `spec/wire-v1.md`.

---

## 1. Identity Keys and Platform Custody

Each Tendril endpoint maintains two long-lived cryptographic keypairs:

| Key | Algorithm | Size | Role |
|---|---|---|---|
| Static keypair | X25519 | 32 B private scalar, 32 B public | Noise `s` key; identifies peer across sessions |
| Signing keypair | Hybrid Ed25519 + ML-DSA-65 | 32 B Ed25519 seed + 32 B ML-DSA-65 seed; `1984 B` public (`32 B` Ed25519 \|\| `1952 B` ML-DSA-65) | Signs grants, rotation records, CRLs, M2M proofs, and pairing key proofs (`3373 B` sig with context `"tendril-hybrid-v1"`); `32 B` Ed25519 prefix authenticates relay mailboxes |

On platforms whose hardware enclaves do not support Curve25519 or ML-DSA-65 directly (for example Apple Secure Enclave or Android StrongBox P-256 enclaves), X25519, Ed25519, and ML-DSA-65 keys are generated in `tendril-core`, persisted wrapped by OS Keychain or Android Keystore AES keys, and zeroized from memory on drop.

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

Hosts MUST reject a 2-group (`TND-XXXX-XXXX`) code when claimed over a remote or relay path unless explicitly permitted by host policy. Section 6.3 defines how the kind of a code is decided and how initiators and URI builders keep a 2-group code off remote paths.

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
- An initiator that pairs from a multi-route URI (Section 6) computes `code_mac` and writes `msg3` only after the `rp` and `rs` checks of Sections 6.4 and 6.5 pass, and only on the single stream it commits (Section 6.6).

### 4.1 Signing Key Claim

A human `PairClaim` carries the initiator's current hybrid signing key so the responder can pin it (for example to add the peer to a group, `groups-v1.md`). `signing_pub` is the `b64url` 1984-byte key and `enroll_proof` the `b64url` 3373-byte hybrid signature that binds it to this handshake and this initiator static key:

```text
key_proof_bytes = "tendril-pair-key-v1\0" (20 B) || h (32 B) || peer_static_pub (32 B)
enroll_proof    = Ed25519(peer_ed25519_priv, key_proof_bytes)
               || ML-DSA-65(peer_mldsa65_priv, key_proof_bytes, ctx = "tendril-hybrid-v1")
```

- `h` is the post-`msg2` handshake hash (the `code_mac` input on Wire v1; `h_post` on Wire v2 PAKE, `wire-v2.md` Section 3.2.2). `peer_static_pub` is the initiator static key authenticated by Noise. The domain differs from the M2M `enroll_proof` domain (Section 7.2).
- A human `PairClaim` MUST carry both `signing_pub` and `enroll_proof`. Responders MUST accept a human claim that carries neither (pre-change initiators) and record no key. A claim that carries exactly one of the two is `protocol_error` and does not burn the code (on Wire v1 the code is not checked; on Wire v2 PAKE it was already authenticated by `msg1` and `init_confirm_mac`).
- The responder verifies and burns the code first (Section 5), then decodes `signing_pub` and `enroll_proof` (`protocol_error` if malformed) and verifies both signature halves strictly against `signing_pub` (`unauthorized` on failure). Any failure leaves the roster unchanged; the code stays burned.
- Recording rules, checked in this order. "Entry" is the one labelled `device_id(peer_static_pub)`; rows 1 and 3 also apply to entries with the same static key under another label (a `host_id`, or a label kept across rotation):

| Existing entry | Effect of the claim |
|---|---|
| `revoked`, or a claimed key that shares identity with a `revoked` entry or trust anchor | `revoked`, nothing changes |
| none | New `pending` entry, with the key if claimed |
| `pending` or `active` with a different pinned key | Keyed claim: `protocol_error`, nothing changes. A pinned signing key changes only through a verified `RotationRecord` chain (`wire-v1.md` Section 4) |
| `pending` with a key, keyless claim | `protocol_error`, nothing changes: the SAS that guards an unconfirmed key is never replaced by a pairing that did not prove it |
| `pending`, no key | Key (if claimed) recorded; SAS replaced; stays `pending` |
| `active`, no key (paired before this section) | Keyed claim: key recorded and the entry returns to `pending`; `pair.confirm` with the new SAS re-activates it, keeping its grants. Keyless claim: SAS replaced, state unchanged |
| `pending` or `active` with the same key, or `active` with a key and a keyless claim | SAS replaced; no key or state change |

- A claimed key is never usable for grant or group decisions until the operator confirms the SAS of the pairing that delivered it.
- **Compatibility (pre-1.0):** a Wire v1 responder built before this section rejects a keyed human claim as `protocol_error` (it requires every M2M field to be absent). Initiators MUST NOT retry without the proof. A Wire v2 responder built before this section accepts the claim and ignores both fields. Peers code-paired before this section have no pinned key until they re-pair and the operator confirms the new SAS.

---

## 5. Pairing Lifecycle and State Transitions

```text
[unpaired] --(pair intent + valid code_mac)--> [pending] --(pair.confirm)--> [active] --(revoke)--> [revoked]
```

- **Default TTL:** 15 minutes (`900 s`), configurable by the host.
- **Live code cap:** At most `MAX_LIVE_PAIRING_CODES = 4` unexpired pairing codes may be live concurrently. Issuing a new code when `>= 4` unexpired codes exist fails closed (`CoreError::ProtocolViolation`), keeping Wire v2 PAKE responders inside the constant-time 4-pass Argon2id padding envelope.
- **Retry budget:** At most **5** failed `pair` claim attempts per code lifetime. Because a wrong-code or MITM-relayed claim cannot be attributed to a single live code in constant time without leaking existence, every failed `pair` claim increments the failure counter on all currently live codes and burns any code reaching 5 failures. To prevent pairing-window status oracles, responders run a uniform dummy KDF pass when zero live codes exist and return the uniform `"unauthorized"` error code across invalid, expired, or burned pairing codes.
- **Single-use burn:** A successful `pair` claim immediately burns the matched code.
- **Route persistence:** Which routes an initiator keeps after a successful pairing, and under which provenance, is decided by Section 6.7.
- **Re-pairing rules:**
  - Re-pairing an already `active` static key updates metadata if needed and stays `active`, except that a verified signing key claim for an `active` entry without a key returns it to `pending` (Section 4.1).
  - Re-pairing a `revoked` static key MUST fail (`Revoked`) and keep the peer `revoked`; the matched pairing code still burns so an attacker cannot probe live codes with a revoked device.
  - A peer in `pending` state MUST NOT open `intent = session` connections until an operator runs `pair.confirm` after comparing `device_fingerprint` and `pairing_sas`. A host MAY tell such a peer that it is still pending with a refusal (`4004 peer_pending`, Section 5.1). Whenever a live pairing SAS was recorded during pairing, `pair.confirm` MUST require explicit SAS matching and MUST fail closed if omitted; out-of-band fingerprint-only confirmation requires an explicit opt-in API or flag (`--allow-no-sas`).
- **Grant separation:** `pair.confirm` marks the roster entry `active` with zero non-session grants by default. Minting capabilities (`pair.mint`) is an independent operation.
- **Symmetric client-side SAS gate & pin protection:**
  - When initiating pairing via an out-of-band pinned URI (`PinnedHost`), the initiator cryptographically verifies the responder's static/signing keys and rotation chain in `msg2` and may record the host pin directly as `active`.
  - When initiating manual unpinned pairing without a pre-shared host key pin, the client MUST record the newly learned host pin in `pending` state awaiting operator SAS confirmation (`pair.confirm`) before allowing `intent = session` connections.
  - **`host_id` form:** a `host_id` is 1 to `MAX_HOST_ID_LEN = 256` bytes, with no ASCII control characters and no `#`. Initiators MUST reject any other `HostHello.host_id` (Wire v1 and Wire v2) as `protocol_error`, pairing URIs carrying such an `id` are invalid, and rosters refuse to store one. A local identity MUST NOT carry one either: configuring, persisting or loading an identity with such a `host_id` fails, so a responder never starts with it.
  - **Pending host store:** until `pair.confirm`, an unpinned `HostHello.host_id` is unauthenticated, so the newly learned host pin is an unconfirmed claim kept in a pending host store, separate from the roster entries, and holds no label: lookups, session gates, route state and enrolment pins by that `host_id` never see it (a session to it fails `PeerPending`). Claims are unique per `(device_id(host_static_pub), host_id)`; a later claim for the same pair replaces the earlier one, and the store holds at most `MAX_PENDING_HOSTS = 64` claims, evicting the oldest. A pairing whose `host_id` already names an `active` entry with the same keys updates that entry instead; one with distinct keys fails (`host_id` collision), as does a revoked label or key.
  - **Confirmation:** `pair.confirm` with a `host_id` selects, among a `pending` entry under that label and the claims naming it, the one that recorded the given SAS; without a SAS (`--allow-no-sas`) exactly one candidate must exist. A selected claim moves to the label as `active`, failing closed with nothing changed when the label is revoked, holds an `active` entry, or holds a pending entry with another static key.
  - **Drop on promote:** whenever a label becomes `active` (confirmation, a verified pin, an M2M enrolment), every claim naming it is dropped. A verified pin replaces an unconfirmed `pending` entry under its label without enforcing that entry's keys or rotation.
  - **Rejection:** removing a pending host drops every claim naming the `host_id` and revokes nothing. `revoke` revokes an `active` or `revoked` entry under the given id directly. Otherwise it first takes the claims whose handshake-authenticated `device_id(host_static_pub)` equals the id, and only when there are none resolves the id like `pair.confirm` against claimed `host_id` values, so no claimed label can redirect or block revoking a claim by its `device_id`. A dedicated claim revocation matches only `device_id(host_static_pub)` and never touches an entry. Revoking a claim drops it and revokes its static and signing keys, never the `host_id` it named: the entry under `device_id(host_static_pub)` records the revocation only when it holds the same static key and no other signing key (a missing signing key is filled from the claim); otherwise a revoked record is kept under a key no `host_id` can take, and no entry holding other keys is revoked. Revoking a key also drops every claim holding it.
  - **Trusted lookups:** enrolment pin checks, Wire v2 secret release, and Day-2 pin snapshots use only `active` entries that no stored CRL revokes. A claim's signing key counts for the responder-side signing key rule of Section 4.1.
  - **Wire floors:** a claim's `min_wire_version` floors its static key (the anti-downgrade check at `msg2` and pinned pairing floors) and carries into a pin written for that static key, but never floors a `host_id`; neither does a `pending` entry.
  - Existing `active` or `revoked` host pins MUST NOT be overwritten with differing cryptographic keys during pairing (`host_id` collisions fail closed without retaining or transferring prior grants).
  - **Stored rosters:** on load, every `pending` entry kept under a key other than `device_id(static_pub)` moves into the pending host store under that label; a `pending` entry under its own `device_id` stays. Stored claims that are not `pending`, carry an invalid `host_id` or static key, or hold a revoked label or key are dropped. Claims never overwrite `active` or `revoked` entries, which keep their keys: a roster does not record whether a revoked entry was ever confirmed, so it keeps blocking its label and keys.

### 5.1 Refusal Notices

A host can tell a known initiator that it is revoked or still pending, instead of dropping the connection silently. The notice is an authenticated refusal: a `0x07 CLOSE` with code `4001 peer_revoked` or `4004 peer_pending` on Wire v1 (`spec/wire-v1.md` Sections 3.3 and 5.4), or a sealed refusal at `msg2` on Wire v2 (`spec/wire-v2.md` Sections 3.1.3 and 3.1.5). A refusal speaks only for the host's own roster entry for the initiator's `device_id`. It never concerns the initiator's pending host store, whose `peer_pending` state is local and fails before any byte is sent.

**Refusal policy.** The host's refusal policy is stored with its roster, sealed with it wherever the roster is sealed, and applies to every listener of the endpoint:

| Field | Default | Meaning |
|---|---|---|
| `pending` | `true` | Refuse `pending` peers with `4004` |
| `revoked_notice_ttl_secs` | `2,592,000` (30 days) | Lifetime of a refusal notice recorded at revocation. `0` records none, so every revocation is silent |

**Recording a notice.** A notice is recorded only when an `active` or `pending` entry transitions to `revoked`, with `until_unix = saturating_add(now_unix, revoked_notice_ttl_secs)`. Revoking an entry that is already `revoked` never creates or extends a notice: with `notify: false` it clears any existing notice and zeroizes its refusal secret, and with `notify: true` it leaves the notice unchanged. On Wire v2 the notice also holds the peer's `reconnect_secret` as its refusal secret, and `mailbox_secret` is zeroized (`spec/wire-v2.md` Section 3.1.1). A notice is live while `now_unix < until_unix`. An `active` entry that a stored CRL revokes is treated as carrying a live notice while `revoked_notice_ttl_secs` is not `0`. Which revocations record a notice:

| Revocation | Notice |
|---|---|
| Operator revoke of a peer | yes, per policy, unless the revoke passes `notify: false` |
| Ingesting a CRL | only when the CRL is the host's own and the caller asks for notices; otherwise silent |
| Fork detection (`spec/wire-v1.md` Section 4.2), in any form | **never**: a fork is a security event |
| Sibling revocation by shared keys, revoking a pending host claim's keys, revoking a trust anchor | never; the primary revoked entry carries the notice |

- Expired notices are pruned whenever the roster is loaded or saved and before a responder classifies an inbound connection. Pruning a notice zeroizes its refusal secret.
- `clear_refusal_notice(peer_id)` drops one entry's notice. The entry stays `revoked`.
- Listeners that serve groups never refuse (`spec/wire-v1.md` Section 5.4.3).
- Every refusal is subject to the refusal limiter (`spec/wire-v1.md` Section 5.4.2). A denied refusal falls back to the silent behaviour.

**Initiator handling.** A refusal does not change the initiator's roster or pin: the application decides. `4001` means the host blocks this device's static key permanently (Section 5.2), so a new pairing needs a new device identity. `4004` means the host has not run `pair.confirm` yet; the initiator MAY retry with backoff. An initiator-side way to forget a host, and serving `/v2/relay` mailboxes to `pending` peers, are specified separately; `revoked` peers are never served a `/v2/relay` mailbox.

### 5.2 Permanent Revocation

Revocation is permanent per static key. A host MUST NOT re-admit a `revoked` static key, by re-pairing (Section 5) or by any host-side "forget" of a revoked entry: grants are bearer documents bound to `device_id`, so re-admitting the key would revive any unexpired grant the device still holds. A host MAY remove a `pending` entry, and MAY silence a revoked entry's refusal notice (Section 5.1), but the entry stays `revoked`. A device that the host revoked re-pairs only with a fresh identity.

A host that keeps roster state both in memory and in storage MUST NOT lose a revocation, revoked trust anchor or CRL when it reloads or commits it, and MUST commit it before admitting or dialing from storage.

---

## 6. Pairing URI Scheme

### 6.1 Format

```text
tendril://pair?v=1&host=<url_encoded_name>&code=<code>&k=<b64url_host_static>&sh=<b64url_host_signing_hash>[&id=<url_encoded_host_id>][&seq=<u64>][&rp=<b64url_relay_key>][&ep=<csv>][&rq=<u64>&rs=<b64url_sig>]
```

- `k` pins the host's valid full-order 32-byte X25519 static public key prior to `msg1` (small-subgroup points MUST be rejected).
- `sh` pins the 32-byte `SHA-256` hash of the host's 1984-byte hybrid signing public key (`SHA-256(Ed25519_pub || MLDSA65_pub)`) as the rotation chain root (or current key at `seq`), keeping QR payloads compact while binding `HostHello.signing_pub` at `msg2` before `msg3` is sent.
- `id` optionally pins the host's expected `host_id` carried in `HostHello`.
- `seq` optionally carries the host's current `rotation_seq` corresponding to `(k, sh)`. When `seq` is omitted on a legacy URI for an already-rotated host presenting a contiguous chain from `seq == 1` ending at `(k, sh)`, initiators MAY verify that chain and initialize the pin at `last.seq`.
- `rp` carries the 32-byte Ed25519 key that selects the host's relay mailbox (Section 6.4). It is `43` base64url characters and MUST decode to a valid Ed25519 point.
- `ep` carries comma-separated endpoint hints (`<provider>:<addr>`), which are dialing hints only and never grant authorization. Each hint is percent-encoded before joining.
- `rq` and `rs` carry the host's route statement (Section 6.5). They are present together or not at all.
- Strict URI validation: parsers MUST reject unknown query parameters (the allow-list is `v`, `host`, `code`, `k`, `sh`, `id`, `seq`, `rp`, `ep`, `rq`, `rs`), duplicate parameters, empty `host`/`code`/`id` values, ASCII control characters (`0x00..=0x1F`, `0x7F`), malformed pairing codes (expecting `TND-XXXX-XXXX` or `TND-XXXX-XXXX-XXXX`), and unsafe/unrecognized endpoint hints (`javascript:`, `file:`, `data:`, non-loopback cleartext `ws://`/`http://`, userinfo `@`, fragments, or link-local/metadata IP hints). `PairClaim` and `HostHello` display/identifier fields with control characters or empty required names MUST likewise fail closed.
- No URI expiry parameter is defined. An opt-in `exp` parameter is proposed separately and is not part of the allow-list.
- A pairing URI hint, stored route or route announcement MUST NOT contain `#`. A relay hint's mailbox key travels in `rp`, never as a fragment.
- Builders emit parameters in the order shown above, with each value in the canonical percent-encoding: unreserved bytes literal, every other byte as `%XX` with uppercase hex. Parsers MUST be handed the exact scanned string; a surface MUST NOT normalize, reorder, or re-encode a URI before parsing it, because `rs` covers its bytes (Section 6.5).

### 6.2 Hard Bounds

| Rule | Requirement |
|---|---|
| Hints per URI | At most `6` (`MAX_PAIRING_URI_ENDPOINTS`), enforced on parse and encode, for `v=1` URIs with or without `rq`/`rs`. |
| Hint length | At most `256` bytes per decoded hint. |
| URI length | At most `1,024` bytes of encoded URI, checked before the query is split. |
| QR soft target | A builder SHOULD keep its output within `711` bytes (QR Version 21, ECC M, byte mode). It reports the URI length and QR version and never drops hints to meet the soft target. |
| Announced set caps | The route set a host advertises (Section 6.11) holds at most `2` hints per provider and `6` in total. A URI carries the announced set after the code-kind filter (Section 6.3) and size trim, so its hints are always a subset of the announced set for its `rq`. |
| `rp` presence | A URI that carries a `/v1/relay` hint MUST carry `rp`. A URI without one MUST NOT. A `/v2/relay` hint does not require `rp`. |
| `rq` form | A decimal `uint64` in `1..=2^53-1`: no sign, no leading zero. `rq` MUST be present if and only if `rs` is present, and MUST be the parameter immediately before `rs`. |
| `rs` form | `86` base64url characters (an Ed25519 signature) and the last parameter. Nothing may follow it. |
| Blocked hint addresses | A `direct:`, bare, `overlay://` or iroh `addr=` hint, or a URL hint's IP host, naming a link-local, unspecified or multicast address, the IPv6 cloud metadata address, a local-use NAT64 address (`64:ff9b:1::/48`) or a Teredo address (`2001::/32`) is `InvalidPairingUri`. The check first unwraps every fixed IPv4 embedding as Section 6.8 does (IPv4-mapped, IPv4-translated, IPv4-compatible except `::` and `::1`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`). |
| IPC hints | `local:` and `unix://` hints still parse (legacy), are never emitted by a builder or in an announcement, and are never dialed or persisted when they come from a URI. A route set containing one is rejected. The `<path>` of an operator hint is a Unix socket path on Unix and a named-pipe path (`\\.\pipe\<name>`) on Windows. |

### 6.3 Code Kind and Path Class

Exactly one classification decides the kind of every pairing code, whether it arrives in a URI, on a command line, or as the `code` argument of a pairing call. The code MUST match `TND` followed by two or three groups of exactly four characters, each an ASCII uppercase letter or digit (`[A-Z0-9]`). The classifier is a format check, not an issuance check: it accepts the `36`-character set `[A-Z0-9]`, a superset of the `31`-character issuance alphabet of Section 3.1, so a manually typed code with `0`, `1`, `I`, `L` or `O` classifies by group count (it can never match an issued code) and is never `PairingCodeInvalid` for its alphabet. Lowercase letters, other characters and any group not of length four are `PairingCodeInvalid`. The kind is the **parsed group count**: two groups (`TND-XXXX-XXXX`, `13` bytes) is `Lan2Group`, three groups (`18` bytes) is `Remote3Group`. Anything else is `PairingCodeInvalid`. Classification neither trims nor changes case; surfaces apply their own input handling first.

**Endpoint provider classes.** A hint's provider is derived from its form:

| Hint form | Provider |
|---|---|
| `local:<path>`, `unix://<path>` | `Local` |
| `direct:<ip>:<port>`, bare `<host>:<port>`, `wt://<host>:<port>[/<path>][?certhash=<43-char-b64url>]` | `Direct` |
| `overlay://<host>:<port>` | `Overlay` |
| `iroh://<node_id>[?addr=...&relay=...]`, `iroh://v2[?relay=...]`, `p2p:iroh://...` | `P2p` |
| `wss://...`, `ws://...` (loopback only), `relay:ws(s)://...` | `Relay` |
| `broker+wss://...`, `broker+ws://...` (loopback only) | `Broker` |

**Rules:**

1. A URI whose hints include any `Remote`-class hint (Section 6.8 rule 2) MUST carry a `Remote3Group` code. A `Lan2Group` URI MUST NOT carry an `Overlay`, `P2p`, `Relay` or `Broker` hint, nor a `direct:`, bare `host:port`, or `wt://` hint whose host is not an IP literal in the loopback or LAN ranges (`InvalidPairingUri`). A `Lan2Group` code claimed on a `Remote` path burns on the responder (Section 3.1).
2. **Client guard.** The initiator applies the guard to the **effective code** (the code actually sent, including an operator override) and to the **actual dial path**. A malformed code fails `PairingCodeInvalid` with zero dials. A `Lan2Group` code is dialed only on candidates whose path class is `Lan` (Section 6.8 rule 2). If none remain, the attempt fails `PairingPathDisallowed` without dialing.
3. **Builder choice.** When the caller does not request a kind (auto), a builder picks `Remote3Group` whenever any `Remote`-class hint survives the caps, so LAN pairing works and a later fallback to a remote rung can never burn the code. It picks `Lan2Group` only when at least one hint survives and every surviving hint is a loopback or LAN `direct:` or `wt://` literal. With **zero** surviving hints the default is `Remote3Group`. An explicit `Lan2Group` request drops every other hint (reason `lan_code_remote_hint`), and an explicit request is never overridden. For auto kind the choice is **re-evaluated after every hint dropped by the size trim** (Section 6.2 `1,024` byte bound): dropping the last remote hint can turn the set into LAN-only literals, which changes the kind from `Remote3Group` to `Lan2Group`. The change only shortens the code, so the trim loop terminates.

### 6.4 Relay Key `rp`

`rp` selects the host's `/v1/relay` mailbox before any key is authenticated. It is a selector, not an authenticator, so every relay key a connect supplies is checked against the authenticated host key. A relay key is a URI `rp` (pairing URI or recovery URI) or a mailbox key typed by the operator as `URL#key`; the check applies when either is present, including a connect that supplies only an operator `URL#key` and no URI.

- After `HostHello` verifies against the pin, the initiator MUST check that each relay key supplied equals the Ed25519 component (the first `32` bytes) of the authenticated `HostHello.signing_pub`. For pairing, the key is the one that verifies against the URI pin. For a session connect (a recovery URI, Section 6.11.4, or an operator `URL#key`), the key is the rotation-authenticated `signing_pub`, and the check runs after the rotation chain verifies and before the rotation is applied. On mismatch it MUST abort before `msg3` (`HostKeyUnverified`).
- An operator `URL#key` MUST also equal a URI `rp` given in the same call; the connect is rejected before any dial otherwise.
- A relay key is never persisted. Day-2 relay dials derive the key from the pinned `signing_pub`.

### 6.5 Route Statement `rs`

A host pin (`k`, `sh`, `seq`) proves who answers. It does not prove that the host chose a route: a URI whose relay URL alone was swapped reaches the genuine host through a relay that forwards, and the pin passes. The route statement is the host's signature over the URI, so the client can tell which routes the host itself authorized.

**Key.** The host signs with the Ed25519 component of its identity hybrid signing key, the key whose public half is `rp` and whose hybrid public key hashes to `sh`.

**Signed bytes.**

```text
rs_input = domain || uri_bytes_before_rs
domain   (26 B) = ASCII "tendril-pairing-routes-v1\0"
uri_bytes_before_rs = the URI string's bytes from the "t" of "tendril://" up to, not including, the "&rs=" that starts the last parameter
rs       = Ed25519.sign(sk_ed25519, rs_input)           // 64 B, base64url without padding: 86 chars
```

- `uri_bytes_before_rs` covers `host`, `code`, `k`, `sh`, `id`, `seq`, `rp`, `ep` and `rq`, byte for byte, in the order emitted. There is no canonicalization: any change to any of them fails verification.
- A parser locates `rs` by requiring the string to end with `&rs=` plus exactly `86` base64url characters, and takes everything before that as the signed prefix. `rs` elsewhere, a second `rs`, trailing bytes, or `rs` without `rq` immediately before it are `InvalidPairingUri`.
- Domain separation: no other Tendril Ed25519 signing input starts with `tendril-pairing-routes-v1\0`, and no other domain is a prefix of it or has it as a prefix. The other domains are the relay domains (`tendril-relay-reg-v1\0`, `tendril-relay-accept-v1\0`, `tendril-relay-ticket-v1\0`, and those of `spec/relay-v2.md`) and the hybrid domains (`tendril-rot-v1\0`, `tendril-grant-v1\0`, `tendril-crl-v1\0`, `tendril-group-v1\0`, `tendril-enroll-v1\0`, `tendril-pair-key-v1\0`, `tendril-route-set-v1\0`), whose Ed25519 halves are plain Ed25519 signatures over the same inputs.
- The signature is classical Ed25519 only: a hybrid signature (`3,373` bytes) does not fit a QR code. Forging `rs` gains control over route metadata only, never session keys. The in-session route announcement (Section 6.11) is hybrid.
- Hosts sign every URI they issue by default. A host MAY opt out and issue an unsigned URI (interop only).

**Verification (pairing)**, in this order, per candidate:

1. `msg2` decrypts and `HostHello` verifies against the URI pin (`k`, `sh`, `seq`, rotation chain), as in `spec/wire-v1.md` Section 3.3.
2. The `rp` check (Section 6.4).
3. The `rs` check against `host_signing_pub`, the chain-verified `HostHello.signing_pub`:
   - No `rs`: result `Unsigned(Absent)`.
   - `SHA-256(host_signing_pub) != sh` (the host rotated after issuance and presented a chain from `sh`): result `Unsigned(KeyRotated)`. The statement is not checked: a key that has been rotated away may be compromised, and a QR rewritten with the old key could otherwise authorize routes.
   - Otherwise `Ed25519.verify_strict(host_signing_pub.ed25519, rs_input, rs)`. On success the verifier re-parses the signed prefix (the exact verified bytes) and the result is `Verified(statement)`; on failure it is `Invalid`.
4. Only then may the initiator activate the candidate and write `msg3` (Section 6.6). No `msg3` byte exists before step 3 completes. An initiator built from a URI enforces steps 1-3 itself: the URI's pin (`k`, `sh`, `id`, `seq`) is the host pin, a separately supplied pin must agree with it (the same `k`; a full signing key or hash matching `sh`; the same `id` when both name one; the same `seq` when the URI carries one), the stricter of the two is used, and a disagreement is `HostKeyUnverified` at `msg2`, and it refuses `msg3` on any failure, deferred or not. `Unsigned(KeyRotated)` is therefore reachable only after a rotation chain from the URI's key verified.

**Authorization reads only verified bytes.** Fields of a parsed URI that a caller can modify (hints, `rq`, `code`) MUST NOT drive authorization. Every persisted route, `rq` value and bound code comes from the re-parsed verified statement. A parsed URI whose public fields no longer match its signed prefix is `Invalid`.

**Failure.** `Invalid` is attempt-fatal before any `msg3`: cancel all candidates (Wire v1) or stop the rung sequence (Wire v2 PAKE), commit nothing, persist nothing, leave the code live, and return `InvalidPairingUri("route statement does not verify")`. A hostile rung cannot produce `Invalid`: a rung that is not the genuine host fails step 1 first. Candidates that present the same chain-verified signing key all get the same answer. Candidates that reach different instances of the genuine host can present different keys (a responder still on the `sh` key gives `Verified` or `Invalid`, a rotated responder gives `Unsigned(KeyRotated)`); the first verified candidate's result decides.

**Verification (session).** On a session connect that carries a recovery URI (Section 6.11.4) or an operator relay key (`URL#key`), the initiator checks, after the rotation chain verifies against the pin and before it applies the rotation or writes `msg3`, on every path whether or not the URI is signed:

1. Every relay key the connect supplies (the URI `rp`, an operator `URL#key`, or both, which must be equal) equals the Ed25519 component of the chain-verified `signing_pub` (`HostKeyUnverified`, Section 6.4). This step also runs on a session connect that supplies only an operator `URL#key` and no recovery URI.
2. If a recovery URI is present, its `k` equals the presented `HostHello` static key and its `sh` equals `SHA-256` of the chain-verified `signing_pub` (`HostKeyUnverified`).
3. If a recovery URI is present and carries `rs`, the route statement verifies against that key (`InvalidPairingUri("route statement does not verify")`). A recovery URI must be issued by the current key, so `Unsigned(KeyRotated)` cannot arise: where pairing would return it, the session check returns `Invalid`.

Any failure leaves the roster unchanged and writes no `msg3`.

### 6.6 Commit Boundary and Candidate Order

| Rule | Requirement |
|---|---|
| Single commit | Per attempt, an initiator writes `msg3` (Wire v1 `PairClaim` with `code_mac` and key proof, or the Wire v2 PAKE claim) on at most one stream, built from that stream's handshake hash `h`. |
| Deferred claim | A multi-route initiator verifies `msg2` and runs the Section 6.5 checks first, and computes `code_mac` (or `init_confirm_mac`) only when it commits. |
| Irrevocability point | The attempt becomes irrevocable **immediately before the first `write` call that carries any `msg3` byte**, not after the write returns. The initiator records that it has committed first, then writes. |
| Ambiguous outcomes | After the irrevocability point, every outcome (write error, partial write, timeout, lost or malformed `PairResponse`, transport close) ends the attempt. No other rung is dialed, no `msg3` is rebuilt, and there is no keyless retry (`spec/wire-v1.md` Section 3.3). |
| Zero-delivery exception | None. No transport proves zero delivery after a write call begins. |
| Result on ambiguity | The transport error is returned with a `committed: true` marker. Nothing is persisted on the client. The host may hold a pending device; recovery is a new code. |

**Candidate order.**

- **Wire v1.** The initiator MAY dial candidates in parallel up to `msg2` verification: `msg1` carries no code material. The first candidate whose `HostHello`, `rp` and `rs` checks pass wins and every other candidate is aborted. Wire v1 charges no code before `msg3`.
- **Wire v2 PAKE.** Every rung that receives `msg1` receives `init_mac`, from which a code guess can be tested offline (`spec/wire-v2.md` Section 3.2.1 note). The initiator MUST therefore try rungs one at a time, in provider order, so the oracle reaches only rungs reached after earlier ones failed. Before commit, any failure (dial, timeout, decoy `msg2`, pin, `rp`) advances to the next rung, except an `Invalid` route check, which ends the attempt.
- **Relays.** `/v1/relay` hints are dialed with `rp`. Wire v2 PAKE pairing runs over the identity mailbox. `/v2/relay` and `iroh://v2` hints require pairwise Wire v2 secrets and are never dialed during Day-1 pairing; ephemeral Day-1 `serve_p2p` advertises a single-use `iroh://<node_id>?relay=...` hint with `Pkarr` disabled instead.

### 6.7 Route Provenance, Policy and Persistence

A route is persisted as a record `(hint, source)`. The source records who authorized it:

| Source | Meaning |
|---|---|
| `operator` | Typed by the local operator or developer: an explicit endpoint on a pairing or connect call, or a route set through a route command or setter |
| `signed` | Host-signed: listed in a `Verified` route statement of a URI whose bound code equals the effective code, in a verified route announcement (Section 6.11), in a verified recovery URI (Section 6.11.4), or in a verified M2M enrollment reply set (Section 7.5) |
| `committed` | The route that carried a successful commit of an **unsigned** pairing, kept because the developer or operator opted in, or the explicit operator endpoint that carried an M2M enrollment (Section 7.5) |

**Independent provenance.** The same hint may be stored once per source. Each record lives and dies by its own source's writers: a signed replacement or announcement never removes or converts an `operator` or `committed` record, and an operator write never touches `signed` records. An operator write that sets at least one route replaces the `committed` record: the operator's routes supersede the route a past commit carried. A dialer contacts each hint once. Stored routes enter the Day-2 candidate list ordered `operator`, `signed`, `committed`; the Day-2 candidate sort puts every `operator` route first, ahead of every provider rung (among them: rung, `iroh://v2` over v1 `iroh://<id>`, `/v2/relay` over `/v1/relay`, IP literal over hostname). All other routes keep rung-first order, with the source (`signed`, then `committed`, then URI hints) as the tie-break inside a rung, ahead of the `iroh://v2` over v1 `iroh://<id>`, `/v2/relay` over `/v1/relay`, and IP literal over hostname preferences. A candidate with no stored source (a URI hint) ranks after both stored sources, so an unverified URI hint never outranks a stored route in the same rung. The strongest source present (`operator` > `signed` > `committed`) decides its egress treatment (Section 6.8). Per-source caps are `6` `operator`, `6` `signed` and `1` `committed`. Under Wire v2, `iroh://v2` and `/v2/relay` hints are never persisted as `committed`, setting an `operator` `iroh://v2` or `/v2/relay` route requires existing `V2PeerSecrets`, and Day-2 sessions suppress stored v1 `iroh://<id>` hints when `iroh://v2` is present as well as same-origin `/v1/relay` hints when `/v2/relay` is present (`superseded_by_v2_route`).

**Route policy.** One client setting, endpoint-wide with a per-call override: `all_signed` (default), `committed_only`, or `none`. A client that opts to save the committed route of an unsigned pairing under `all_signed` does so explicitly; with `none` that request is a usage error, and with `committed_only` it is redundant.

"Signed and bound" means the route check is `Verified(statement)` **and** the effective code is byte-equal to the code inside the verified statement (never a field of a mutable parsed URI).

| Situation | `all_signed` (default) | `committed_only` | `none` |
|---|---|---|---|
| Signed and bound, success | Every non-IPC hint of the statement as `signed`, including hints this client cannot dial (portable rosters; egress re-applies at dial time), merged under the high-water rule below | The winner as `signed` only if the winner's **original hint string** (before prefix strip, resolution or normalization) is one of the statement's hints; an explicit operator endpoint winner stays `operator`. Same merge rule | Nothing from the URI |
| `Verified` but the effective code differs (code override), success | Unsigned rules | Unsigned rules | Unsigned rules |
| `Unsigned(Absent)` or `Unsigned(KeyRotated)`, success | **Nothing.** With the explicit committed-route opt-in: the committed route as `committed`. The result reports no persisted routes and the reason (`unsigned_uri` or `route_key_rotated`) | The committed route as `committed` | Nothing |
| `Invalid` | Attempt aborted before `msg3` (Section 6.5) | Same | Same |
| Explicit operator endpoint, success | That endpoint after operator normalization, as `operator`, plus the URI rows above | Same | That endpoint only |
| Any failure or ambiguous commit | Nothing | Nothing | Nothing |

**Route high-water mark.** Code binding proves the code belongs to that issuance, not that its routes are the newest: a host can have two live QR codes at `rq = 4` and `rq = 5`, and a client that already learned `5` may pair with the still-unused `4`. Every pairing write therefore merges against the **latest** stored state read under the same lock that writes the pin, never a snapshot from before pairing began. The stored route metadata is `route_meta = {seq, issued_at, origin}` with `origin` one of `Uri`, `Session` or `Approved`.

| Stored `route_meta.seq` vs the statement's `rq` | `signed` records | `route_meta` |
|---|---|---|
| No metadata, or `rq > seq` | Replaced by the statement's hints | `{seq: rq, issued_at: none, origin: Uri}` |
| `rq == seq`, stored `route_meta.origin` is `Uri` or `Session` | Union of stored and statement hints, then the caps after this table. Both are subsets of the same announced set, so the union is at most `6` | Unchanged |
| `rq == seq`, stored `route_meta.origin` is `Approved` | Every `Approved` record is preserved and never replaced or unioned away. The statement's other hints are unioned with the stored non-approved `signed` records, then the caps after this table apply to the result | Unchanged |
| `rq < seq` | Unchanged; result reason `stale_route_seq` | Unchanged |

After every equal-sequence merge the provider and total caps (`2` per provider, `6` total, Section 6.2) apply to the merged `signed` set, dropping the lowest-ranked non-approved routes first, so an `Approved` set never loses a record to a statement. An approved older QR can hold up to six hints disjoint from the current announced set at the same high-water `seq`, which is why the union is capped after the merge and is not assumed to stay within one announced set. `operator` records are never touched by a pairing write; the `committed` record is replaced only by a new `committed` entry or an operator route write (independent provenance above). `route_meta.seq` is never lowered or cleared by any writer. Pairing succeeds in every row: the code was consumed and the keys verified; only route freshness differs.

**Why unsigned URIs persist nothing by default.** There is no authenticated way to tell that a URI should have carried `rs` (`HostHello` cannot grow a field), so stripping `rs` is undetectable. A default that saved unsigned routes would let a stripped URI with a swapped relay persist the attacker's relay as a durable metadata tap.

**Day-2 contact.** Day-2 auto-dial contacts only persisted routes. Legacy `relay_hints` saved by earlier versions are display data and are never auto-dialed.

### 6.8 Egress Policy

Applies at dial time to URI hints and to `committed` and `signed` routes (including announced ones). `operator` routes get only the always-blocked set and the code-kind guard. Any resolution failure, lookup timeout or zero answers rejects the hint, and one failing address rejects the hint. Every blocked or dropped hint is reported in the attempt result with a reason, and no dial is attempted for it.

**Enforcement through connect.** A check counts only if the connect uses the checked answer:

| Scheme | Enforcement |
|---|---|
| `direct:` | IP literals only. Names are dropped (`direct_requires_ip_literal`). |
| `wt://` | HTTP/3 over QUIC (`wt://<host>:<port>[/<path>][?certhash=<43-char-b64url>]`). Requires an explicit non-zero port and at most one `certhash` parameter decoding to 32 bytes (pinned via `serverCertificateHashes`; when omitted, native WebPKI roots apply). Hostnames are resolved once through the checked resolver, every answer is screened, and the QUIC connect dials only a checked address while preserving TLS SNI. |
| `overlay://` | Plain TCP. The dialer resolves once, checks every address, and connects to the checked literal. |
| `ws(s)://`, `/v1/relay`, `/v2/relay`, `broker+ws(s)://` | The URL is not rewritten, so TLS SNI, certificate verification and the `Host` header keep the original authority. The checked resolution is the one the TCP connect uses. |
| `iroh://` | Hint dialer **without address lookup**: no Pkarr, no DNS address lookup, no other lookup service. The dial address holds the node id (or the hourly epoch `EndpointId` derived from `mailbox_secret` when dialing `iroh://v2`), the `relay=` URLs that are members of the dialer's configured relay map (all of the map when no hint relay is a member, and falling back across remaining map relays on `iroh://v2`), and on v1 `iroh://` only the `addr=` literals that pass the `direct:` rules (`iroh://v2` MUST reject `?addr=`). A hint relay outside the map is dropped (`iroh_relay_not_configured`); an empty map with no surviving `addr=` skips the hint. Client `port_mapping` defaults to `false` and `iroh://v2` / ephemeral Day-1 listeners keep `Pkarr` off. Lookup must be off because a lookup result is inserted into the remote's candidate paths and a relay connection is opened to any URL given. |
| `local:`, `unix://` | From a URI: dropped (`ipc_from_uri`). Operator endpoints only. |

**Destination classes** (canonical addresses, IPv4-mapped IPv6 unwrapped):

| Class | Addresses |
|---|---|
| Blocked | unspecified, multicast, broadcast, link-local, `0.0.0.0/8`, `240.0.0.0/4`, cloud metadata |
| Loopback | `127.0.0.0/8`, `::1`, `localhost` |
| LAN | RFC 1918, IPv6 ULA `fc00::/7` |
| Overlay | RFC 6598 `100.64.0.0/10` |
| Public | anything else |

**Rules:**

1. Blocked addresses are never dialed, from any source.
2. **Path class for the code guard.** A candidate is `Lan` only if its provider is `Local` or `Direct` **and** every checked destination is Loopback or LAN. Everything else is `Remote`. The responder classifies a pairing connection by its provider in the same way.
3. Loopback is allowed for URI, stored and announced hints (same-machine pairing and tests). The only effect is one Tendril preamble plus `msg1` written to a local port.
4. Browsers have no resolver access: they apply the syntactic checks, a scheme filter and the provider half of rule 2, and the browser's own network rules apply beyond that.

**Disclosure before `HostHello`.** Automatic contact (Day 1) reaches the URI hints that pass this policy. Each route operator sees the client IP and port and timing, plus TLS SNI for `wss://`. A `/v1/relay` operator also sees `rp`, which links the client to the host. An `iroh://` hint reaches a relay in the dialer's configured map only, and the node id. Wire v1 `msg1` discloses the preamble and ephemeral keys and no code material. Wire v2 `msg1` additionally discloses `channel_salt` and `init_mac`, an offline code-guess oracle (`spec/wire-v2.md` Section 3.2.1 note), which is why Section 6.6 makes Wire v2 rungs sequential.

### 6.9 Relay Credentials

Relay admission credentials are configured once by the developer or operator, never by an end user. A relay ticket is a bearer token whose `relay_host` excludes the port, so host equality is not origin equality. The same holds for HMAC proofs, which bind the challenge host without a port. One rule covers both:

- Admission material (ticket or HMAC) is attached only when the dial URL's origin `(scheme, host, port)`, with default ports made explicit, is **byte-equal** to a configured relay-auth origin, or the dial target is the explicit operator endpoint of the call. Host equality, a matching ticket `relay_host` or a matching challenge host is never enough.
- Origins learned only from a URI, a stored `signed` or `committed` route, or a route announcement never receive credentials. If such a relay demands authentication the candidate fails with reason `relay_auth_unconfigured` and the race continues.
- Every surface that can attach admission material applies the same origin match before it attaches anything.

### 6.10 Host Advertising

| Host | Mode | Sources of hints |
|---|---|---|
| Command-line `serve` | Explicit only | Concrete listener binds and explicitly advertised endpoints. Unspecified binds never enumerate interfaces. |
| SDK and FFI hosts | `auto` (default) or `explicit` | Explicit: as above. Auto: explicit sources **plus** the enumeration below. |

Only `/v1/relay` URLs where the pairing listener holds the identity mailbox are advertised as relays. Explicit `serve_p2p_v2` / `--p2p-v2` listeners advertise `iroh://v2?relay=<home>` without persistent `EndpointId` or `?addr=`, and ephemeral Day-1 `serve_p2p` listeners omit `Pkarr` publication. Explicit non-v2 `iroh://` hints carry `addr=` only with explicit direct-address advertising.

**Auto enumeration** applies to every pairing-capable TCP listener bound to an unspecified address. An address is advertised only if the listener accepts on it **and** it sits on an eligible network:

1. **Source.** Each address carries its interface and transports (`Wifi`, `Ethernet`, `Cellular`, `Vpn`, `Other`). Desktop platforms and iOS enumerate interfaces that are up and not loopback. Android uses the multi-network snapshot the binding supplies; it never enumerates natively.
2. **Listener coverage.** A `0.0.0.0` bind covers IPv4 only. A `[::]` bind covers IPv6, and IPv4 only when `IPV6_V6ONLY` is `false` (read back after bind). An address outside a listener's coverage is never advertised for it.
3. **Eligible networks.** A network is eligible only if it has `Wifi`, `Ethernet` or `Vpn`, or (desktop only) `Other` on a non-tunnel interface. An address on a network whose only transport is `Cellular` is never auto-advertised.
4. **Classes.**
   - LAN: RFC 1918 or ULA on an eligible non-`Vpn` network: `direct:<ip>:<port>` (IPv6 bracketed).
   - Overlay: an address in `100.64.0.0/10` or a ULA, **with overlay evidence**: the network has `Vpn`, or its interface name starts with `tailscale`, `wg`, `zt`, `utun` or `tun`. The hint is `overlay://<ip>:<port>`. An address range alone is never evidence: carrier-grade NAT on cellular uses `100.64.0.0/10`.
   - Loopback, link-local, Blocked and Public addresses are never auto-advertised.
   - A listener bound to a concrete address is advertised as that address (an explicit source) whatever its class, except Blocked.
5. Order IPv4 before IPv6 within a provider, then by interface index; the announced-set sort and caps (Section 6.11.1) apply after.
6. **Snapshot retention (Android).** The host keeps the last snapshot and reuses it on a refresh without one. A snapshot with zero networks is debounced `30 s`; after the debounce a confirmed empty snapshot is applied and the addresses of lost networks are retired. Timer refreshes never reuse addresses from a network that is no longer present.

**Privacy.** Auto advertising selects only LAN and overlay addresses and never a public one. A public address appears only when the developer binds a listener to it or lists it explicitly. The QR and every announcement carry whatever the set holds. A QR is a picture: anyone who photographs, screenshots or is forwarded it learns the advertised addresses and `rp` (the live code is single-use and expires). Applications that must not reveal these addresses use `explicit`.

### 6.11 Route Announcements

A signed route announcement keeps a paired client's `signed` routes current. It is one host-signed statement: the host's identity, a persistent monotonic sequence, an issue time and a route list. Its frame is `0x0C ROUTE_SET` (`spec/wire-v1.md` Section 5.2).

#### 6.11.1 The announced set

For each `seq` the host has exactly one announced set `C(seq)`. It is built from the host's current hints in this order:

1. **Normalize** listener output: bare `ip:port` becomes `direct:ip:port`; strip a relay `#<mailbox>` fragment (a `/v1/relay` fragment must equal the identity's Ed25519 key, which becomes `rp`); drop `iroh://` `addr=` parameters until the hint fits `256` bytes. `local:` and `unix://` input is dropped (`ipc_not_advertised`).
2. **Validate** each hint (syntax and the always-blocked set on literals). No DNS.
3. **Deduplicate** exact strings.
4. **Sort** by `(provider rank, non-numeric host, destination order, original index)`, where destination order is, for `Direct`, `0` for a loopback or LAN IP literal and `1` otherwise (LAN `direct:` literals stay ahead of public ones), for `Overlay`, `0` for an IPv4 literal and `1` otherwise (so a Tailscale `100.64.0.0/10` address stays ahead of its ULA), and `0` for every other provider.
5. **Provider cap:** keep the first `2` per provider.
6. **Total cap:** keep the first `6`.

Every URI issued with `rq = seq` carries `C(seq)` after the Section 6.3 kind filter and the size trim, never a hint outside `C(seq)`. An equal-sequence announcement is therefore a superset of the routes a client stored from a QR with the same `rq`, and applying it can only add routes. There is no per-issue extra endpoint: additional hints go through the host's advertised endpoints, which change `C` and bump `seq`.

#### 6.11.2 Host sequence

- The host persists `{seq, issued_at, digest, routes}` with its roster, where `routes` is `C(seq)` and `digest = SHA-256(count || routes)` in the body encoding of `spec/wire-v1.md` Section 5.2.
- **Bump rule.** Under the store lock, if no state exists or the digest of the recomputed set differs, set `seq = old_seq + 1` (first value `1`), `issued_at = now`, store the digest and routes, and persist **before** anything is signed or sent. Otherwise the stored state is returned. `seq` never decreases while the roster survives, so it is monotonic across restarts.
- **Exhaustion.** If the set changed and `old_seq == 2^53-1`, the bump fails (`ProtocolViolation("route sequence exhausted")`) and changes nothing: no changed set is ever signed at the capped `seq`. Signed issuance fails with that error (an operator can issue unsigned). An unchanged set at the cap still returns the stored state.
- **Single publication path.** One routine recomputes the set, applies the bump rule and schedules sends. URI issuance calls it first and builds the URI from the returned state (`rq = seq`, hints from `routes`). It decides what to send by comparing the returned `seq` with the last `seq` each live session has been sent or reported, never by whether this call changed the digest.
- **Triggers.** SDK and FFI hosts with `auto` advertising recompute on a platform network-change signal and on a `60 s` timer. Every SDK and FFI host recomputes when a listener is served or stopped or its advertised endpoints or relay configuration change. Command-line `serve` recomputes at startup and when a listener is added or removed at runtime.

#### 6.11.3 Client acceptance

The client applies an announcement under its store lock, in this order:

1. The peer entry exists, is `Active` and not revoked by a CRL; else ignore (`PeerInactive`).
2. `static_pub` equals the entry's static key and `sh` equals `SHA-256(entry.signing_pub)`; else ignore (`KeyMismatch`). The session's final authorization check has already made the pin equal the session keys, so a rotated host announces under its new, pinned key.
3. The hybrid signature verifies under `entry.signing_pub`; else ignore (`BadSignature`).
4. `issued_at <= now + 86,400`; else ignore (`FutureIssuedAt`). This bound is clock-skew protection, **not** replay protection (that is step 5); acceptance does not otherwise depend on clocks.
5. Sequence: with no `route_meta`, accept. With `route_meta = m`: accept iff `seq > m.seq`, or `seq == m.seq` and `m.origin == Uri`. Else ignore (`StaleSeq`); replays and reordering land here. An equal sequence is accepted only over a URI-origin set because `C(seq)` is a superset of every QR issued at `seq`. An approved replacement (`origin == Approved`, Section 6.11.4) is never replaced by an equal-sequence set, so only a strictly newer host set can replace it.
6. Apply atomically in one roster transaction: remove every `signed` record, insert the set's routes as `signed`, and set `route_meta = {seq, issued_at, origin: Session}`. `operator` and `committed` records are never touched, including records whose hint also appears in the set (independent provenance, Section 6.7).

Policy: a client applies announcements only under `all_signed`. Under `committed_only` and `none` it ignores them entirely, including removals, and never sends `route_seq`, so a conforming host never sends it a `0x0C`. Durability: the transaction has the same atomic-replace behaviour as every roster write.

#### 6.11.4 Recovery and fresh QR codes

- A fresh signed URI is also a route set: hints plus `rq`, signed by the current key. A client applies it **offline** when the URI's `k` and `sh` match the pinned keys, or **in-session** as a recovery URI when the host rotated. A recovery URI's code is ignored and never sent.
- `rq > route_meta.seq` (or no metadata): under `all_signed` the URI's non-IPC hints replace the `signed` routes and `route_meta = {seq: rq, issued_at: none, origin: Uri}`.
- `rq <= route_meta.seq`: a stale or equal URI never replaces routes by itself. The hints are used for that dial only, and replace the `signed` records only with explicit approval, after which `route_meta = {seq: max(stored, rq), issued_at: none, origin: Approved}`. Under `all_signed`, `Approved` makes the client send that `seq` as `route_seq` and reject equal-sequence sets (Section 6.11.3 step 5), so the approval holds until the host publishes a strictly newer set.
- Under `committed_only` and `none`, recovery URIs replace routes only with explicit approval. An unsigned recovery URI never changes routes.
- **Recovery bootstrap after rotation.** Only a **signed** recovery URI (one that carries `rs`) contributes discovery inputs: its non-IPC hints that are not already stored may be dialed as discovery candidates before its statement verifies. An unsigned recovery URI adds no candidates. The following rules hold for those hints:
  - **Egress.** Every hint passes the full egress policy (Section 6.8: blocked destinations, resolution rules, the `Lan2Group` path guard) like any other candidate. A hint that fails is skipped with its reason.
  - **Stored `/v2/relay` gate.** A `/v2/relay` hint from a recovery URI is treated like a stored route, and no mailbox id or relay-auth material is derived for it unless **all** hold: the entry is the one being connected, looked up by the roster key passed as the target (never by a URI `id` or a hint); it is `Active` and not CRL-revoked; it holds the Wire v2 secrets; the exact route is already in that entry's stored routes with source `operator` or `signed`; and the driver is Wire v2. A relay hint that is not already authorized for the target by these rules fails the gate, is skipped (`relay_v2_not_authorized`) and triggers no derivation. It becomes eligible on a later connect once the URI's routes are applied.
  - **No writes before verification.** No route is written, replaced or marked `signed`, and no `route_meta` changes, until the statement verifies under the rotation-authenticated key learned on that connection. The `k`, `sh`, relay key and `rs` checks of Section 6.5 still run before `msg3`.
- Recovery routes are applied only after the client's final authorization check (peer `Active`, not revoked, wire floor respected, session keys equal to the pin) passes. If that check fails, authenticated evidence (a rotation, a CRL) is persisted separately and recovery routes are not applied.
- **Offline application** requires a verified statement under the pinned signing key of the `Active` entry whose static key and `sh` match the URI, applies the same `rq` rules, and uses no network and no code.
- **All-dead routes.** If every stored route is dead (for example the host moved networks while the client was offline), the client cannot learn new routes from the host. Guidance: advertise a configured relay as a stable anchor; otherwise apply a fresh signed QR.

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

In `msg3`, an M2M initiator omits `code_mac` and populates `enrollment_token`, `signing_pub` (`b64url` 1984-byte hybrid Ed25519 || ML-DSA-65 public key matching `enroll_proof`), and `enroll_proof` (`b64url` 3373-byte hybrid signature using ML-DSA-65 context `"tendril-hybrid-v1"` over the Noise transcript binding `h`, initiator static public key `peer_static_pub`, and `token.nonce`):

```text
enroll_proof_bytes = "tendril-enroll-v1\0" (18 B)
                  || h (32 B)
                  || peer_static_pub (32 B)
                  || UTF-8(enrollment_token.nonce)

enroll_proof = Ed25519(peer_ed25519_priv, enroll_proof_bytes)
            || ML-DSA-65(peer_mldsa65_priv, enroll_proof_bytes, ctx = "tendril-hybrid-v1")
```

Responders MUST verify both signature halves of `enroll_proof` strictly against `signing_pub` before accepting enrollment, ensuring the claim cannot be replayed into a different Noise session or substituted for a different static identity.

### 7.3 Initiator Pinning Requirement

M2M initiators MUST supply an out-of-band `PinnedHost` (static X25519 key, root/current hybrid signing key pin as either full 1984-byte key or 32-byte SHA-256 hash, `host_id`, optional `rotation_seq`) and verify the responder's `HostHello.signing_pub` (and `RotationRecord` chain if rotated) at `msg2` before transmitting `msg3`. Unpinned TOFU is forbidden in M2M mode.

### 7.4 Atomic Single-Use Burn Log and Default-Deny Roster Entry

- Responders persist `burned_enrollment_nonces` (`nonce -> not_after_unix`) alongside `Roster`, bounded at `16_384` active entries (`MAX_BURNED_ENROLLMENT_NONCES`). Expired entries (`not_after <= now`) are pruned before capacity checks; if all `16_384` slots remain unexpired, new enrollments fail closed (`EnrollmentBurnLogFull` / `"rate_limited"`).
- On a valid M2M `PairClaim`, the responder MUST atomically check and record `token.nonce` in `burned_enrollment_nonces` and persist the `Roster` BEFORE calling `record_enrolled_machine` and BEFORE writing `PairResponse` to the wire. If the enrolling peer static key is `Revoked` or collides with an existing entry, registration fails closed (`Revoked`), while the token nonce remains burned so a revoked device cannot probe live tokens.
- `record_enrolled_machine` transitions the peer directly into `Active` state with `(static_pub, signing_pub)` and zero application grants (`PairResponse.status = "active"`). Application authorization still requires separate `pair.mint` delegation.

### 7.5 Host-Signed Routes in the Enrollment Reply

An enrolled initiator needs a route to the host for Day 2 (Section 6.7). The host supplies its announced route set (Section 6.11) in the enrollment reply, signed with the same key the initiator verified at `msg2`.

**Request.** `PairClaim.route_seq` (`0..=2^53-1`, M2M claims only) asks for the set. The initiator sends it only under route policy `all_signed`, with the value `SessionHello.route_seq` would carry for the pinned `host_id` (`wire-v1.md` Section 5.2.2), else `0`. Under `committed_only` and `none` it omits the field. A human claim that carries `route_seq` is `protocol_error` and does not consume the code: on Wire v1 the code is not checked, and on Wire v2 PAKE the code is not burned.

**Reply.** A responder that registered the peer (Section 7.4, `status = "active"`) adds `PairResponse.route_set` if and only if the claim carried `route_seq`, the responder holds route state (Section 6.11.2), and its `seq > route_seq`. The value is the unpadded base64url encoding of the `0x0C` payload (`wire-v1.md` Section 5.2.1) for the stored `C(seq)`, `seq` and `issued_at`, hybrid-signed by the host's current signing key. These are the bytes the host would announce. The set is signed after the nonce burn and registration and before `PairResponse` is written. A responder that cannot produce the set (no route state, a signing failure, or a reply over the frame bound) omits the field and the enrollment result is unchanged.

**Size.** The largest payload is `5,003` bytes, which is `6,671` base64url characters. The largest `PairResponse` (a `20`-character `device_id`, the `2,646`-character `host_signing_pub` and a maximal `route_set`) is `9,408` bytes of JSON. One `msg4` frame carries at most `65,503` bytes of transport plaintext (frame `len <= 65,519` including the `16`-byte AEAD tag, `wire-v1.md` Section 2.2), so the reply stays one frame.

**Initiator checks**, after the existing `PairResponse` checks (`device_id`, `status`, and `host_signing_pub` equal to the chain-verified `HostHello.signing_pub`), in this order:

1. If the claim did not request a set, `route_set` is ignored without being decoded. A human initiator on either wire never requests one: a `PairResponse` that carries `route_set` is a protocol violation for it (on Wire v2 it would also break the `msg4` size buckets).
2. Decode: the value must be a JSON string of at most `6,671` characters that decodes as strict unpadded base64url to a payload passing the structural rules of `wire-v1.md` Section 5.2.3 step 4. Any other value is `malformed`: a longer string is not copied, and a non-string value (including one nested past any parser depth limit) is skipped without being built, so no `route_set` value can make the reply undecodable.
3. Key binding: the payload's `static_pub` equals the responder static key authenticated by this Noise handshake, and its `sh` equals `SHA-256` of the chain-verified signing key (the pin's key, or the key its `RotationRecord` chain reached at `msg2`). Otherwise `key_mismatch`. A set signed by a key rotated away is never accepted.
4. Both signature halves verify strictly under that key. Otherwise `bad_signature`.

A failure at steps 2 to 4 drops the set and surfaces a typed warning with the reason. The enrollment still succeeds: the token is already burned and both keys are proven. A dropped set changes nothing in the roster.

**Pin checks before the token is sent.** The initiator never spends the token on a conflict it can detect locally:

1. Before writing `msg1`, it checks its pin against its own roster and stops when the pin write after enrollment is certain to fail: an entry, CRL or revoked trust anchor that revokes the pinned label or keys, or a stored entry at the same or an older `rotation_seq` whose keys differ from the pin. An unscoped pin (no `host_id`) is matched to a stored entry by its static key, for this check and for the `route_seq` it requests.
2. When the roster holds the pinned host at a higher `rotation_seq` than the pin, the stored entry (its static key, full signing key and `rotation_seq`) replaces the pin. An older pin would accept a key the host has rotated away from, which may be compromised.
3. The claim is deferred: after `msg2` verifies and before any `msg3` byte, the initiator dry-runs the pin write for the host `msg2` actually authenticated (`HostHello.host_id`, static key, chain-verified signing key and `rotation_seq`) against its latest roster. A conflict (a revoked label, key or Ed25519 half, a CRL, another key already pinned under that `host_id`) ends the attempt with no `msg3`. This also covers unscoped and hash pins.

**Persistence.** In one roster transaction under the store lock, after the host pin is written as `active` (Section 5; a re-enrollment keeps the entry's display name):

1. Under `all_signed`, a verified set is applied by the client acceptance rules of Section 6.11.3 (issue time bound, sequence rule, atomic replacement of the `signed` routes, `route_meta = {seq, issued_at, origin: Session}`).
2. Unless the policy is `none`, the explicit operator endpoint that carried the enrollment is stored as the `committed` route on every enrollment, alongside any applied set, after operator normalization. It replaces any earlier `committed` record, so a host whose public address changed is re-enrolled through the new address without the old one sticking. It is never a hint-derived, URI-learned or redirected endpoint. It passes the operator route checks (URL syntax, blocked literals); a `URL#key` must name the Ed25519 half of the pinned signing key; a `direct:` endpoint must be an IP literal, because Day 2 cannot dial a name; and the `committed` rules apply, so an IPC (`local:`, `unix://`) or `/v2/relay` endpoint is not stored.

Under `none` nothing is stored and no set is requested. On Day 2 `operator` routes sort first, ahead of every rung, and inside a rung `signed` sorts before `committed` and both before URI hints, ahead of the `/v2/relay` and IP literal preferences (Section 6.7), so a host-signed route is tried ahead of the enrollment endpoint whenever both sit in the same rung. Later announcements replace the `signed` routes as usual and never touch the `committed` record; an explicit operator route write replaces it (Section 6.7).

A route that is not stored (an ignored or refused set, an unstorable operator endpoint) is a warning, never an enrollment failure. The pin is written regardless. A pin conflict found only after the handshake fails as in Section 5.

**Compatibility (pre-1.0).**

- `PairResponse` and `PairClaim` are parsed with unknown fields rejected. An initiator built before this section rejects a `PairResponse` that carries `route_set`, after its token was burned. A responder therefore sends `route_set` only when the claim requested it.
- A responder built before this section rejects a claim that carries `route_seq` as `protocol_error`. It parses the claim before any token check, so the nonce is not burned and the token stays usable. Enrollment against such a host fails until it is upgraded. An initiator MAY retry on a new connection without `route_seq` and learn no route; this is accepted before 1.0, as in Section 4.1.
- An initiator built after this section accepts a reply without `route_set` (an older responder, or one without route state) and still stores the operator endpoint.
- Requesting is opt-in per call. In `tendril-runtime`, only `drive_m2m_enroll_initiator_with_routes` (with explicit options) sends `route_seq` and stores routes; `drive_m2m_enroll_initiator_with_store` sends no `route_seq`, stores no route and enrolls against older hosts as before, while still pinning the host. The command line (`tendril enroll`, `--route-policy`), the C ABI (`tendril_endpoint_enroll_initiate`) and the Python and Node bindings (`enroll_initiate`, `enrollInitiate`) call it with their route policy and the endpoint dialed; an endpoint without a state directory has no store to hold routes, so it uses neither the request nor the storage and pins the host in memory only.

# Tendril Small Peer Mesh Groups Specification v1

Status: **Normative (v1)**

Conventions follow `spec/wire-v1.md`, `spec/wire-v2.md`, and `spec/grants-v1.md`. A group links up to 32 devices that each enrolled once with a group root. Every sibling link is an independent pairwise `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` session; the group adds a signed membership manifest, a rendezvous key for first contact, and gossip of newer manifests. Relays stay stateless and learn nothing about groups.

`tendril-core` is Sans-I/O. It never performs I/O and never ingests a received frame on its own: runtimes pass `0x0A` and `0x0B` payloads to `GroupBook` explicitly.

---

## 1. Limits

| Constant | Value | Rule |
|---|---|---|
| `MAX_GROUP_MEMBERS` | `32` | Active entries in `members` |
| `MAX_GROUP_CO_ADMINS` | `8` | Enforced by the builder API only (Section 6.3) |
| `MAX_MEMBER_ENDPOINTS` | `8` | Endpoint hints per member, each `<= 256` characters |
| `MAX_MEMBER_CAPS` | `16` | Capability strings per member |
| `MAX_REVOKED_MEMBERS` | `256` | Entries in `revoked_members` |
| `MAX_GROUP_MANIFEST_LEN` | `32768` | Compact JSON length of a signed manifest in bytes |
| `MAX_MANIFEST_VALIDITY` | `90 days` | Maximum `expires_at - ts` |
| `MAX_GOSSIP_GROUPS` | `16` | Entries in `SessionHello.groups` |
| `MAX_GROUP_SEQ` | `2^53 - 1` | Largest `seq` in a manifest, `0x0B` frame, or gossip entry |
| `MAX_GROUP_SEQ_JUMP` | `1024` | Largest `seq - local_seq` accepted when ingesting a known group |
| `GROUP_RENDEZVOUS_FRAME_LEN` | `60` | Exact `0x0B` payload length |
| `MAX_LOCAL_GROUPS` | `16` | Groups one endpoint is an active member or root of; a further group is refused, never pinned. Groups the endpoint was removed from do not count |
| `MAX_STORED_GROUPS` | `64` | Stored group records of any role, including groups the endpoint was removed from; a further first-contact pin is refused until a group is forgotten. Updates of a stored group are always accepted. On removal or revocation of a non-root endpoint, its rendezvous and pairwise secrets are dropped and only the manifest is kept |
| `MAX_GROUPS_PER_SIGNER` | `4` | Stored records created by first-contact pins (R1) attributed to one paired peer. A record is attributed by the identity handles of the authenticated sender at pin time: the roster key, stored `device_id`, and static-derived `device_id` of its roster entry and of every entry sharing its static key or signing identity. A pin is refused (`GroupUnauthorized`) while 4 stored records share a handle with the sender, every role counted, including groups the endpoint was removed from. Other records do not count. Updates of a stored group are quota-exempt but follow all other ingest rules |

The size cap is authoritative. A manifest whose members each carry eight 256-character endpoint hints exceeds it; a realistic 32-member manifest (two hints of about 40 characters and four capabilities per member) is about 20 KiB and fits.

---

## 2. Identifiers

```text
group_id = "grp_" || hex_lower(SHA-256(root_signing_pub)[0..8])
```

`root_signing_pub` is the 1984-byte hybrid signing public key of the founding root device. A `group_id` is exactly 20 ASCII characters (`grp_` plus 16 lowercase hex characters). The founding root key is immutable for the life of the group.

Device identifiers follow `device_id = "dev_" || hex_lower(SHA-256(static_pub)[0..8])`.

---

## 3. `GroupManifest`

```jsonc
GroupManifest = {
  "v": 1,
  "group_id": string,                 // grp_...
  "name": string,                     // 1..=64 characters, no control characters
  "seq": uint64,                      // 1..=2^53-1
  "min_wire_version": 1 | 2,          // never decreases across seq
  "ts": string,                       // RFC 3339 UTC, whole seconds, "Z"
  "expires_at": string,               // RFC 3339 UTC, whole seconds, "Z"
  "root_signing_pub": string,         // b64url 1984 bytes
  "signer_device_id": string,         // root device or co-admin
  "signer_signing_pub"?: string,      // b64url 1984 bytes; present iff signer is a co-admin
  "admin_grant"?: Grant,              // present iff signer is a co-admin
  "members": [GroupMember],
  "revoked_members": [string],        // device_ids, permanent
  "sig": string                       // b64url 3373 bytes, hybrid Ed25519 || ML-DSA-65
}

GroupMember = {
  "device_id": string,
  "name": string,                     // 1..=64 characters, no control characters
  "static_pub": string,               // b64url 32 bytes, valid full-order X25519 key
  "signing_pub_hash": string,         // b64url 32 bytes, SHA-256(member 1984-byte signing key)
  "relay_pub": string,                // b64url 32 bytes, Ed25519 prefix of the member signing key
  "endpoints": [string],              // <= 8 hints, each <= 256 chars
  "caps": [string]                    // <= 16 group-scoped capabilities
}
```

- Unknown fields MUST be rejected at every level. `signer_signing_pub` and `admin_grant` are omitted when unset; an explicit JSON `null` for either is rejected at parse time.
- Members are pinned by `signing_pub_hash` and `relay_pub`, as in `spec/pairing-v1.md`. A member's full signing key arrives in `HostHello.signing_pub` when its sibling dials it.
- Endpoint hints use the pairing endpoint-hint validator (`is_valid_pairing_endpoint_hint`), which strips metadata and link-local targets, plus the `256` character bound. `local:` and `unix://` hints are rejected because manifests are shared with other devices.

### 3.1 Canonical Signing Input

```text
signed_bytes = "tendril-group-v1\0" (17 B) || UTF-8(RFC8785_JCS(manifest without "sig"))
```

The signature is the hybrid `Ed25519 || ML-DSA-65` signature of `spec/grants-v1.md` (ML-DSA context `tendril-hybrid-v1`). Both components MUST verify. The signing key is `root_signing_pub` when `signer_device_id` is the root device, otherwise `signer_signing_pub`.

### 3.2 Wire Size

The serialized compact JSON manifest MUST be `<= 32768` bytes. The bound is enforced when signing and when ingesting (`GroupManifestTooLarge`). It is also the maximum `0x0A` payload length.

---

## 4. Rulings

| Id | Ruling |
|---|---|
| R1 | Accept a manifest iff its signature is valid, `seq > local_seq`, and `seq - local_seq <= 1024` (`MAX_GROUP_SEQ_JUMP`, `InvalidGroupManifest`). `seq` is always in `1..=2^53-1`, enforced when signing, verifying, and decoding `0x0B`. `seq == local_seq` with different signed bytes is `GroupManifestFork`; identical signed bytes is a no-op. `seq < local_seq` is `GroupSeqRollback`. The first ingest of an unknown group pins `root_signing_pub` (trust on first use through an explicit administrative push). A runtime pins a group pushed as `0x0A` over a session only when the authenticated sender is the manifest's `signer_device_id`, is an `Active` ordinarily paired peer, its pinned signing key equals the manifest signing key (`root_signing_pub` for the root, else `signer_signing_pub`), the local device is an active member, and fewer than `MAX_GROUPS_PER_SIGNER` stored records are attributed to that peer. The sender's roster entries are every entry whose static key derives its device id (a reverse pairing can leave a host label and a `dev_` entry): the pin is refused if any is `Revoked` or CRL-revoked, and otherwise one `Active` entry with that signing key suffices, whatever the key order. Every later manifest MUST carry the pinned root key. Gossip MUST NOT create groups. |
| R2 | The compact JSON manifest is `<= 32768` bytes (Section 3.2). |
| R3 | The founding root device MUST appear in `members` in every manifest with `signing_pub_hash == SHA-256(root_signing_pub)` and `relay_pub == root_signing_pub[0..32]`. Neither the root nor any co-admin may remove or revoke it. The root entry's `device_id` and `static_pub` are pinned at the first ingest and MUST be identical in every later manifest. A co-admin-signed manifest MUST carry the root entry byte-identical (every field, including `name`, `endpoints`, and `caps`) to the stored manifest's root entry (`GroupUnauthorized`); only root-signed manifests may change its mutable fields. |
| R4 | `revoked_members` is a superset of the previous manifest's set, has at most 256 entries, and no revoked id appears in `members`. Every `device_id` present in the previous `members` and absent from the new `members` MUST appear in the new `revoked_members` (`InvalidGroupManifest`). Member `device_id` values and `signing_pub_hash` values are unique. |
| R5 | Each `member.caps` entry parses as a capability (`spec/grants-v1.md` Section 1), has a `resource`, and that resource equals `group_id` or starts with `group_id + "/"` with no empty, `.`, or `..` path segment and no `%` or `\` character. `group.admin` MUST NOT appear in `member.caps`. Admin authority comes only from `admin_grant`. |
| R6 | `ts` and `expires_at` are whole-second UTC. `ts < expires_at <= ts + 90 days`. Ingest requires `now < expires_at` and `ts <= now + 30 s`. A stored manifest that later expires stays stored, and group authorization against it fails closed. |
| R7 | `min_wire_version` is `1` or `2` and never decreases across `seq` (`GroupWireDowngrade`). |
| R8 | A `0x0B` frame is accepted only from the root device or the signer holding a valid `admin_grant` in the stored manifest, and only when its `seq` equals the stored manifest `seq`. The grant is re-verified at delivery time (window with 30 s skew, `root_crl`), and the stored manifest MUST be unexpired. When the manifest that set the stored `seq` grew `revoked_members`, a `0x0B` carrying the key held from an older `seq` is rejected: revocation requires a rotated key. Non-admins never forward it. Locally installing a key (`GroupBook::install_secrets`) applies the same two checks: the key `seq` equals the stored manifest `seq`, and after a revocation the key differs from the previously stored key. |
| R9 | `SessionHello.groups` is optional and omitted when empty. Peers built before this change reject the unknown field; this is acceptable before 1.0. |
| R10 | Core performs no I/O and never auto-ingests. Runtimes wire frames to `GroupBook`. |

---

## 5. Verification Algorithm

`verify_group_manifest(manifest, now, root_crl)` performs these checks in order and fails closed at the first failure:

1. Serialized length `<= 32768` (`GroupManifestTooLarge`).
2. `v == 1`, `group_id` well formed, `1 <= seq <= 2^53-1`, `min_wire_version` in `{1, 2}`, `name` valid (`InvalidGroupManifest`).
3. `root_signing_pub` is a valid hybrid key and `group_id` equals the derivation of Section 2.
4. Validity window and clock skew (R6).
5. `1 <= len(members) <= 32`. For each member: valid name, valid X25519 `static_pub`, `device_id == device_id(static_pub)`, 32-byte `signing_pub_hash`, valid Ed25519 `relay_pub`, endpoint hints (Section 3), capability scope (R5, `InvalidGroupCapabilityScope`). Reject duplicate `device_id` or `signing_pub_hash`.
6. `revoked_members` well formed, unique, `<= 256`. A member id also in `revoked_members` is `GroupMemberRevoked`.
7. Locate the root device by `signing_pub_hash == SHA-256(root_signing_pub)` and require `relay_pub == root_signing_pub[0..32]` (R3).
8. If `signer_device_id` is the root device: `signer_signing_pub` and `admin_grant` MUST be absent.
   Otherwise: the signer MUST be an active member, `signer_signing_pub` MUST be present and match the member `signing_pub_hash` and `relay_pub`, and `admin_grant` MUST be present and valid for that exact signer key (Section 5.1, `GroupUnauthorized`).
9. Verify the hybrid signature over `signed_bytes` (`InvalidSignature`).

Ingest (`GroupBook::ingest_group_manifest`) then applies, against the stored manifest of the same `group_id`: pinned root key equality, then R1 sequence rules and jump bound, R7 wire floor, R4 revoked superset (a re-added revoked member is `GroupMemberRevoked`) and removal-implies-revocation, the pinned root identity (R3), and for co-admin-signed manifests the byte-identical root entry (R3). A manifest identical to the stored one is a no-op, but only while it is unexpired: an identical replay of an expired manifest is rejected as expired.

### 5.1 `admin_grant`

`admin_grant` is a `Grant` (`spec/grants-v1.md`) that MUST satisfy all of:

- signed directly by the root (`issuer == root device_id`, empty `delegated_from`, no `uses` or `machine`);
- `subject == signer_device_id`;
- carries the exact capability string `group.admin:<group_id>/<hex_lower(SHA-256(signer_signing_pub))>`, where `signer_signing_pub` is the 1984-byte signing key of the co-signer. The match is exact string equality: a bare `group.admin:<group_id>` grant, a wildcard, or a grant keyed to another key does NOT authorize co-signing. Without the key binding, anyone who has seen a co-admin manifest could lift its public `admin_grant` and sign with a key of their own;
- valid at `now` with the standard 30 s skew on `not_before` and `now < not_after`;
- not revoked by the effective root revocation set (Section 5.2): revoked when it lists `signer_device_id` or the root `device_id` in `revoked_devices`, or the grant `nonce` in `revoked_nonces`. Labels are not compared.

### 5.2 Live Authority

Every admin decision after ingest (`authorize_group` for `group.admin`, `0x0B` ingest, `GroupBook::is_group_admin`) takes `now` and the optional root CRL and re-verifies the stored `admin_grant` (Section 5.1) against them. The founding root is always an admin while the stored manifest is unexpired. Bootstrap derivation (Section 8) and `0x0B` ingest fail closed on an expired stored manifest.

The effective root revocation set of a group is the union of every stored CRL with `v == 1` whose signature verifies under the group's pinned `root_signing_pub`, wherever it is stored: under a roster entry's key, stored `device_id`, or static-derived `device_id`, under the root `device_id`, or under the local `host_id`. Sequence numbers are per issuer label and are not compared across labels. The set covers the CRLs stored now: a later root-signed CRL replaces the earlier one under the same label, so an entry the root leaves out of it stops applying unless another stored CRL still lists it. The set is unresolvable, and every decision that consumes it fails closed (`GroupUnauthorized`), when the roster entry keyed by the root `device_id` is not `Pending`, has rotated keys (`rotation_seq > 0`; `RotationRecord`, Section 4 of `spec/wire-v2.md`), and no longer pins `root_signing_pub`, whether or not a re-signed CRL has arrived, or when the CRL stored under the root `device_id` does not verify under `root_signing_pub` and either the endpoint is the root itself (its `host_id` equals the root `device_id`), that key is held by no entry, or the entry is not `Pending` and its keys were rotated. A local root fails closed whenever the CRL under its own label does not verify under its key, whatever entry a peer pinned there. A roster entry does not record where its key lineage started, so every such rotated entry, `Active` or `Revoked` (including a never-confirmed pin later revoked locally), counts as the root's and the set fails closed. A `Pending` entry under that key, such as an unconfirmed host pin whose `host_id` the remote chose, counts as no entry for these two rules: it never closes a group, and a local root holding one under its own `device_id` still fails closed once its CRL is re-signed under a rotated key. A CRL signed by any other key never applies. Group decisions match `revoked_devices` against member `device_id` values only.

### 5.3 Co-Admin Limit

`MAX_GROUP_CO_ADMINS = 8` is enforced by the builder API (`issue_admin_grant` refuses when the root reports 8 live grants). Verification does not count co-admins: the manifest does not list every grant the root has issued, so only the root can track the number.

---

## 6. Capabilities

| Capability | Meaning |
|---|---|
| `group.admin:<group_id>/<hex_lower(SHA-256(signer_signing_pub))>` | Co-sign manifests and deliver `0x0B`, bound to one signing key. Never appears in `member.caps`; granted only through `admin_grant`. Admin checks use the request form `group.admin:<group_id>`. |
| `group.send:<group_id>` | Send application data to peers of the group. |
| `group.recv:<group_id>` | Receive application data from peers of the group. |

Application capabilities such as `sync.push:<group_id>/wiki` or `kv.write:<group_id>` are valid in `member.caps` under R5. `authorize_group(group_id, sender_device_id, cap, now, root_crl)` fails closed when the group is unknown, the stored manifest has expired, the sender is revoked by the manifest or listed in `root_crl`, the sender is not a member, the requested capability is not group-scoped, or no member capability covers it. `group.admin` is satisfied only by the root device or the signer of the stored manifest holding a live `admin_grant` (Section 5.2), and only for the exact request `group.admin:<group_id>`; any `group.admin:<group_id>/<suffix>` request is denied.

---

## 7. Frames

| `frame_type` | Name | Payload |
|---|---|---|
| `0x0A` | `GROUP_MANIFEST` | Compact UTF-8 JSON `GroupManifest`, `<= 32768` bytes |
| `0x0B` | `GROUP_RENDEZVOUS` | `20 B ASCII group_id || 8 B uint64_be seq || 32 B group_rendezvous_key`, exactly 60 bytes |

Both are valid on Wire v1 sessions and inside Wire v2 `0x09 PADDED` envelopes (`spec/wire-v1.md` Section 5, `spec/wire-v2.md` Section 5). A receiver closes the session on a `0x0A` payload above 32768 bytes or a `0x0B` payload of any other length than 60. On Wire v2 the legacy unpadded receive path accepts only `0x01..=0x07`; bare `0x0A` and `0x0B` are rejected as unknown frame types under every padding policy, including a disabled one, so they travel only inside `0x09 PADDED`; a Wire v2 session with padding disabled cannot send or receive group frames. A received `0x0A` is surfaced as a parsed but unverified manifest; a received `0x0B` as a decoded frame whose key is held in zeroizing storage and redacted in `Debug` output. Neither is authorized or stored until the runtime calls `GroupBook`.

`GroupBook::ingest_group_rendezvous(sender_device_id, frame, now, root_crl)` applies R8, rejects a `seq` below or above the stored manifest `seq`, and rejects a different key for a `seq` that already holds one. A fresh key is generated on group creation and on every removal; adding a member keeps the key and re-binds it to the new `seq`.

---

## 8. Sibling Bootstrap Derivations

Both use HKDF-SHA256 (`hkdf_sha256_32`: extract with `salt`, one expand block) over the 32-byte `group_rendezvous_key`, with `salt = uint64_be(seq)`:

```text
pair_bootstrap = HKDF(ikm = key, salt = seq_be8,
                      info = "tendril-group-v2-rendezvous\0" || min(id_a, id_b) || "\0" || max(id_a, id_b))
group_mailbox  = HKDF(ikm = key, salt = seq_be8,
                      info = "tendril-group-v2-mailbox" || member_device_id)
```

`min` and `max` compare the ASCII `device_id` strings bytewise, so both members derive the same `pair_bootstrap`.

A sibling is pinned by the `static_pub` and `signing_pub_hash` in the stored manifest alone. The dialer resolves the full 1984-byte signing key from `HostHello` and MUST abort before `msg3` when its SHA-256 differs from `signing_pub_hash` or the Noise static differs from `static_pub`. A `HostHello` rotation chain never advances a sibling pin: sibling keys change only through a signed manifest update.

Sibling state is group scoped. Siblings never enter the endpoint's global trust roster, so a sibling cannot open an ordinary session or receive a grant without explicit pairing. Pairwise `V2PeerSecrets` are stored per group and per sibling next to the manifest, and are deleted when any ingested manifest revokes or removes the sibling, and when the group is forgotten.

The bootstrap only gates discovery: identity is authenticated by the Noise statics and the manifest signing pins, and the bootstrap changes with `seq`, so it rotates on every revocation. Pairwise agreement:

- The responder accepts `msg1` under either the stored pairwise secret or the current-`seq` `pair_bootstrap`.
- The initiator dials with the stored pairwise secret first. When that handshake fails it retries once with `pair_bootstrap`. Without a stored pairwise secret it dials with `pair_bootstrap`.
- A session admitted under `pair_bootstrap` overwrites the stored pairwise secret on both ends with its exported secrets, after `Established`. A session admitted under the pairwise secret keeps it.
- When both siblings dial each other at once, both ends keep the link initiated by the lower `device_id`, and pairwise secrets are persisted only from that surviving link.
- A persistence failure closes the link; it is never ignored.
- When `min_wire_version >= 2`, both ends refuse Wire v1 sibling sessions.

Admission and authority are re-evaluated against the current manifest and the founding root's CRL, never against a cached decision:

- A link is published only after its membership, static pin, wire floor, and CRL status are checked again following pairwise persistence, so a revocation, key rotation, or CRL entry that lands during persistence refuses it and removes the secrets it persisted.
- A change to either the stored manifest or the root CRL closes every link whose peer is no longer an active, CRL-clean member with the pinned static key.
- Every `0x01`, `0x0A`, and `0x0B` write re-checks recipient authority (and sender capability for `0x01`, admin authority for `0x0B`) while holding the session writer, immediately before sealing; a write queued before a capability or membership change is dropped.
- Wire floors are per context. A session counts as a sibling session only when the initiator advertises exactly that group, the peer is an active member pinned with its static key, its wire version equals the group's wire floor, and on Wire v2 it was admitted under that member's pairwise or bootstrap secret for that group. Any other session is ordinary and must meet the ordinary peer's persisted floor.

Onboarding: a member that holds the manifest but not the current-`seq` key cannot derive `pair_bootstrap`, so on Wire v2 no sibling link to it can exist. The root or co-admin therefore delivers `0x0A` and `0x0B` over its ordinary paired session to the member (Section 4, R1 and R8):

- An admin sync uses an existing sibling link when one is live. Otherwise, when the member is an `Active`, CRL-clean ordinarily paired peer whose pinned static key equals the manifest's, it opens an ordinary session with that peer's persisted secrets and wire floor, writes the stored `0x0A` and, when it is an admin holding the current key, the `0x0B`, then sends `0x05 PING` and closes after the matching pong. The member is reported delivered only after the pong, which it sends after reading both frames. Any other member is dialed as a sibling. Each frame re-checks recipient and admin authority under the session writer as above.
- A member's group listener admits a session that is not a sibling session only as an ordinary session from that group's root or live co-admin: its persisted roster entry is `Active`, CRL-clean, has the authenticated static key and a floor the session meets (on Wire v2 its own reconnect secret admitted `msg1`), and the stored manifest names it as root or as the signer holding a live `admin_grant` with the same static key. Such a session ingests only that group's `0x0A` (as an administrative push) and `0x0B`, never delivers application data into the group, and closes when the peer closes or after 10 seconds without a control frame. A listener serves at most 4 such sessions at once.
- A host that runs ordinary sessions itself passes every received `0x0A` and `0x0B` to the same runtime ingestion, which applies R1 first-contact pinning and R8, and refuses a `0x0B` for a group the local device was removed from.

A key installed this way is picked up by the member's open group listener without a restart.

Known limitation: when one initiator establishes two bootstrap-admitted links to the same sibling at once (for example over two paths), the lower-`device_id` rule does not separate them and the two ends can persist the exported secrets of different links. The next dial then fails under the stored pairwise secret and recovers through the single `pair_bootstrap` retry, which overwrites both ends again. While the current-`seq` key is unavailable to either end, those siblings cannot reconnect until it is delivered.

---

## 9. Gossip (`SessionHello.groups`)

```jsonc
SessionHello = { ..., "groups"?: [{ "group_id": string, "seq": uint64 }] }
```

- At most 16 entries, each a well-formed `group_id` with `1 <= seq <= 2^53-1`, no duplicate `group_id`. An empty array is invalid and MUST be omitted.
- A responder that holds a higher `seq` for a shared group MAY queue its stored manifest as `0x0A`. The receiver ingests it through the gossip path, which never creates a group and never trusts anything beyond the pinned root key.
- `SessionHello` is sent by the initiator only, so an initiator cannot learn the responder's `seq`: after `Established` an initiator pushes its stored manifest as `0x0A`, and a responder pushes only when its `seq` exceeds the advertised one (a missing entry counts as `0`). Receivers treat an older or identical manifest as a no-op.
- An endpoint advertises only the group of the session it is dialing, never its other groups.
- `0x0B` is never gossiped by non-admins. An admin MAY push the current key to a member after `Established`.

---

## 10. Error Names

`InvalidGroupManifest`, `InvalidGroupCapabilityScope`, `GroupSeqRollback`, `GroupManifestFork`, `GroupMemberRevoked`, `GroupNotFound`, `GroupUnauthorized`, `GroupManifestTooLarge`, `GroupWireDowngrade`.

---

## 11. Vectors

`spec/vectors/groups.json` contains the deterministic key set, the `group_id` derivation, a six-manifest chain (root-signed and co-admin-signed with a key-bound `admin_grant`, ending in a revocation), the signed bytes of each, rejection cases (host-path scope escape, cross-group capability, sequence rollback, revoked re-add, co-admin removing the root, wire downgrade, 33 members, oversize, `group_id` mismatch, expiry, tampering, forged co-admin with a swapped key, bare admin grant, `seq = 2^53`, sequence jump above 1024, removal without revocation, co-admin rewriting the root entry, `%` and `\` in capability resources), parse rejections (explicit `null` for `signer_signing_pub` and `admin_grant`), the `pair_bootstrap` and `group_mailbox` HKDF outputs, the `0x0B` frame, and a `SessionHello.groups` example. Rust and Go verify every value byte for byte.

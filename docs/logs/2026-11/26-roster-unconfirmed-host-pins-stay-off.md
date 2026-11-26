---
type: Log Entry
title: "roster: unconfirmed host pins stay off the host_id they name"
description: "Unpinned pairings keep the learned host pin in a separate pending host store until pair.confirm, host_id values are bounded and hash-free, and trusted lookups use only active, unrevoked entries."
tags: [log, update]
kind: Update
status: stable
---

roster: unconfirmed host pins stay off the host_id they name:

- `Roster::record_pending_host` keeps an unpinned pairing's host pin in a pending host store (`Roster::pending_hosts`, serialized as `pending_hosts`), unique per `(device_id(static_pub), host_id)` and capped at `MAX_PENDING_HOSTS` (64, oldest evicted). A claim holds no label, so it never blocks a later pairing, enrolment or session for that `host_id`.
- `confirm_peer` with the `host_id` and the pairing SAS moves the matching claim to the label as `Active`; with no SAS exactly one candidate must exist. Every transition of a label to `Active` (confirmation, `insert_pinned_host`, `record_enrolled_machine`) drops the claims naming it, and a verified pin replaces an unconfirmed `Pending` entry under its label.
- `remove_pending_peer` drops every claim naming the id. `revoke_peer` matches a claim's `device_id(static_pub)` before any claimed `host_id`, and `Roster::revoke_pending_host` (also on `WasmRoster`) matches only that id; both revoke the claim's keys, never the `host_id` and never an entry holding other keys; an ambiguous revocation is a protocol error, also over FFI. `WasmRoster::pending_hosts_json` lists the claims.
- `host_id` values are 1 to `MAX_HOST_ID_LEN` (256) bytes with no control characters or `#` (`identity::is_valid_host_id`): enforced on `HostHello` (Wire v1 and v2), pairing URI `id`, roster writes and persisted identities, with `EndpointIdentity::try_with_host_id` for callers.
- Enrolment pin checks in the runtime driver, `Roster::pin_snapshot`, the WASM v2 secret lookups and the FFI v2 mailbox lookups use only `Active` entries that no stored CRL revokes.
- A claim's Wire v2 floor applies to its static key (pairing floors, the `msg2` downgrade check, and pins written for that key), never to a `host_id`; `Pending` entries floor no label. Responder-side signing key checks include claims.
- Stored rosters migrate on load: `Pending` entries kept under a key other than their own `device_id` move into the pending store, and claims holding revoked keys are dropped; `Active` and `Revoked` entries keep their keys.
- Updated `spec/pairing-v1.md` Section 5.

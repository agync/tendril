---
type: Log Entry
title: "surfaces: list, remove and revoke pending host claims"
description: "The CLI, C ABI, Python, Node and Web client list, drop and revoke the unconfirmed host claims of unpinned pairing; revocation matches only the handshake-derived device_id."
tags: [log, update]
kind: Update
status: stable
---

surfaces: list, remove and revoke pending host claims:

- `tendril pending list`, `tendril pending remove <host_id>` and `tendril pending revoke <device_id>` manage the unconfirmed host claims left by unpinned pairing.
- The C ABI adds `tendril_endpoint_pending_hosts`, `tendril_endpoint_remove_pending_host` and `tendril_endpoint_revoke_pending_host`; Python and Node add `pending_hosts`, `remove_pending_host` and `revoke_pending_host` (`pendingHosts`, `removePendingHost`, `revokePendingHost`); the Web client adds `pendingHosts`, `removePendingHost` and `revokePendingHost`. `Roster::remove_pending_host_claims` drops claims only, never an entry.
- A claim is revoked only through `Roster::revoke_pending_host` by the `device_id` derived from its static key in the handshake; a claimed `host_id` never matches. The shared listing is `Roster::pending_hosts_json`.
- Updated `docs/reference/ffi-and-bindings.md`.

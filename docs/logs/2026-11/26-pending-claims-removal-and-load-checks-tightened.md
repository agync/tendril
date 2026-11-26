---
type: Log Entry
title: "surfaces: claim removal never touches entries, host_id and CRL checks tightened"
description: "Removing pending host claims drops claims only, revoking one refreshes the M2M flag, local identities are validated at every load, and change-only enrol persistence keeps every CRL it kept before."
tags: [log, update]
kind: Update
status: stable
---

surfaces: claim removal never touches entries, host_id and CRL checks tightened:

- `Roster::remove_pending_host_claims` drops the claims naming a `host_id` and nothing else, and fails with `PeerNotFound` when none does. The CLI, C ABI (`tendril_endpoint_remove_pending_host`), Python (`remove_pending_host`), Node (`removePendingHost`) and Web (`removePendingHost`) use it, so a hostile host naming the id of an inbound `Pending` device cannot remove that device, and an `Active` or `Revoked` entry reports not found. `remove_pending_peer` keeps its old meaning.
- `Roster::pending_hosts_json` is the one claim listing for the CLI, C ABI, Python, Node and `WasmRoster::pending_hosts_json`, so every surface emits the same fields.
- `tendril_endpoint_revoke_pending_host` and the Python and Node `revoke_pending_host` refresh the M2M flag, because revoking a claim also revokes trust anchors sharing its signing key. `tendril_endpoint_pending_hosts` clears `out_json` on every error and reports storage and I/O failures as `TENDRIL_ERR_INTERNAL`.
- Every endpoint constructor (C ABI, Python, Node) and the WASM identity save refuse a local identity whose `host_id` fails `is_valid_host_id`; load paths already did. `EndpointIdentity::with_host_id` is hidden from the docs: it exists for tests that forge hostile hosts.
- The C ABI enrol pre-persist keeps a CRL issued by this host and a CRL whose issuer was revoked on disk meanwhile, verifying each against the same keys as the single-CRL persist path.

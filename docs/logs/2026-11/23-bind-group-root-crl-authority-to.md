---
type: Log Entry
title: "Bind group root CRL authority to the founding root key"
description: "Apply every stored revocation list signed by a group's founding root key, whatever its roster label, and fail closed once a member applies the root's key rotation."
tags: [log, update]
kind: Update
status: stable
---

Bind group root CRL authority to the founding root key:

- **Core (`tendril-core`):** New `group::root_crl` resolver. Every stored list with `v == 1` whose signature verifies under the group's pinned `root_signing_pub` applies, under any roster entry key, entry `device_id`, the root `device_id`, or the local `host_id` (a core-API root minting its own lists under a `host_id` that differs from its `device_id`); several such lists merge as a union because `seq` is per label. The group's revocation state is unresolvable (`GroupUnauthorized`) once the entry keyed by the root `device_id` has applied a verified rotation away from the founding key, before or after a re-signed list arrives, or when a list under the root `device_id` no longer verifies and is held by no entry or by a rotated entry. Both rules treat a `Pending` entry under the root `device_id` as no entry: an unconfirmed host pin whose remote-chosen `host_id` collides with the root `device_id`, even one claiming a rotation, never closes a group, and a local root holding one under its own `device_id` still fails closed once it re-signs its list under a rotated key. Any other rotated entry there, `Active` or `Revoked` (including a never-confirmed pin later revoked locally), fails closed, because a roster entry does not record where its key lineage started. `admin_grant` checks no longer compare the list issuer with the root `device_id`.
- **Local root:** A local root (its `host_id` equals the root `device_id`) fails closed whenever the list under its own label does not verify under the founding key, so a confirmed peer that chose that label and replaced the list there with its own higher-seq list cannot make the resolver return no list.
- **Runtime and browser (`tendril-runtime`, `tendril-wasm`):** Pools, the hub, pushed `0x0A` and `0x0B` ingest, and `WasmGroupBook` read the root list only through the resolver. The hub resolves it before the Wire v1 floor narrows the roster. A pool whose root list becomes unresolvable closes its open links as well as refusing new decisions. A pushed `0x0B` for a group that is not stored when the list is resolved is refused before the group book write. A rotated runtime root now fails its groups closed on members instead of dropping its revocations.
- **Spec (`spec/groups-v1.md`):** Section 5.1 and Section 5.2 define the effective root revocation set.
- **Design (`docs/design/groups.md`):** Trust model CRL row updated. The "Root CRL key" limitation is gone; "Rotated host-labeled root" covers core-API roots whose label differs from their `device_id`, and "Colliding host label" covers a rotated, non-`Pending` entry (`Active` or `Revoked`) under a root's `device_id`.

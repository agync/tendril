---
type: Log Entry
title: "Cap first-contact group pins per paired peer"
description: "Limit the groups one paired peer can pin through first contact to MAX_GROUPS_PER_SIGNER = 4, tracked by the peer's identity handles; group books written now do not load in older binaries."
tags: [log, update]
kind: Update
status: stable
---

Cap first-contact group pins per paired peer:

- **Core (`tendril-core`):** New `MAX_GROUPS_PER_SIGNER = 4`. `check_first_contact` returns the sender's identity handles (roster key, stored `device_id`, and static-derived `device_id` of its entry and of every entry sharing its static key or signing identity), and `GroupBook::ingest_first_contact_manifest` refuses a new pin (`GroupUnauthorized`) while 4 stored records share a handle with them, or when it is given no handles. Groups the endpoint was removed from still count; forgetting a group frees a slot. Updates of a stored group are quota-exempt but follow every other ingest rule. This closes the co-admin route where one peer minted throwaway roots and filled every local slot.
- **Reverse-paired peers (`tendril-core`, `tendril-runtime`):** A reverse pairing can leave two roster entries for one peer (a host label and a `dev_` entry sharing the static key). `check_first_contact` and `group_add_member` used the first matching entry in key order, so a `Pending` or keyless alias that sorted first refused the peer. The new `resolve_group_peer` refuses when any matching entry is revoked or CRL-revoked and otherwise selects an `Active` entry with a signing key (equal to the manifest signer key for first contact). `group_add_member` matches the stored or static-derived device id.
- **Runtime and browser (`tendril-runtime`, `tendril-wasm`):** Pushed manifests (`ingest_pushed_manifest`, `group_ingest_manifest`, `WasmGroupBook`) apply the quota; the count and the pin share one group book write. Both re-export the constant.
- **Persisted format:** Each group record created by first contact stores `pinned_by`. New binaries load older group books (their records count for nobody), but **an older binary fails to load a group book that carries `pinned_by`**. Acceptable before 1.0.
- **Spec (`spec/groups-v1.md`):** Section 1 adds the constant; R1 adds the quota.
- **Docs (`docs/design/groups.md`, `docs/usage/cli-demo.md`):** Trust model and bounds updated. The "No per-signer quota" limitation is replaced by the residual: a peer that gains a new roster entry after reaching the cap (a host pin under a new label, or a reverse pairing after a key rotation) and then rotates keys through that entry only starts a new quota.

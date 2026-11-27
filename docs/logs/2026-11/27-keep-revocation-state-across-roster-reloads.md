---
type: Log Entry
title: "Keep revocation state across roster reloads and commits in the FFI, Python, Node and CLI"
description: "One fold keeps CRLs, fork and claim revocations and revoked anchors across every reload and commit of a store-backed endpoint."
tags: [log, update]
kind: Update
status: stable
---

Keep revocation state across roster reloads and commits. `Roster::absorb_held_revocations` folds the revocation state an in-memory roster holds into the stored one: CRLs (verified against a fixed key order, the host's own CRL only by its own key), revoked entries and anchors, a tombstone where disk rotated or replaced a record memory revoked, and each refusal notice from the pair of rosters alone. `RosterAccess` runs its read, fold, save and publish under one hold of the roster file lock and gains `commit_held_revocations`, `reload` and `with_local_signer`. The FFI, Python, Node and CLI drop their own copies, commit before every store-backed driver reads the roster, and commit after any event that can revoke. A revoked static key stays revoked across a restart (`spec/pairing-v1.md` Section 5.2). The C ABI does not change.

---
type: Log Entry
title: "Groups on sealed Kotlin and Swift endpoints"
description: "Kotlin and Swift endpoints with a state directory now host groups: the runtime seals roster and group state itself under an identity-derived key, with the desktop transaction model."
tags: [log, update]
kind: Update
status: stable
---

Groups on sealed Kotlin and Swift endpoints:

- **Sealed state (`crates/tendril-core/src/state_seal.rs`, `crates/tendril-runtime/src/store.rs`):** `StateStore::open_sealed` keeps the roster and group book in `rt-roster.sealed` and `rt-groups.sealed`, XChaCha20-Poly1305 under `HKDF-SHA256(X25519 static secret, "tendril-local-state-v1")`, with the kind bound only through the AAD. Transactions keep the per-file `flock` and reload inside the lock, so independent handles never lose updates. A corrupt, tampered, foreign, or wrong-kind file fails closed.
- **Android locking (`crates/tendril-runtime`):** std `File::lock` is unsupported on Android, so the state store takes its `flock` through `rustix` there (new Android-only dependency).
- **Durability (all state stores, desktop included):** every state write now syncs the directory after the rename and reports `state commit not durable` when that fails, so success means the commit survives a crash. Every open syncs the directory and walks up its canonical path syncing each ancestor, stopping without error at the first one the process may not open (an app sandbox root), so a retry after an interrupted first open never treats an existing tree as durable.
- **C ABI (`crates/tendril-ffi/include/tendril.h`):** additive `tendril_endpoint_new_sealed(state_dir, identity_json_opt, roster_json_opt, host_id_opt)`. Group admin calls, pools, the hub, session group frames (`group_manifest_ingested` instead of `_unverified`), and CRL and v2 floor persistence work unchanged on it. Existing runtime state without an identity is refused, an open without an identity writes nothing, and a roster seed needs the saved identity and is parsed and written only when neither runtime file exists.
- **Kotlin and Swift:** `TendrilEndpoint.create(stateDir)` and `TendrilEndpoint(stateDir:)` use the sealed constructor, keep only the identity binding-sealed (temp file synced before the move), and no longer write the roster. Identity bootstrap runs under an exclusive lock on `.identity.lock`, so concurrent first opens share one identity, and a generated identity is saved before any runtime state exists. The legacy binding `roster.sealed` is read only when no runtime state exists, seeds `rt-roster.sealed` once, and is then deleted (a leftover is deleted unread), so a downgrade to an older binding starts with an empty roster. Swift excludes the state directory from backups.
- **Known limitation:** whole-file replay of an older authentic state file by someone who can write the app's private directory is not detected; see "Local state replay" in [Groups](../../design/groups.md).
- **Tests:** seal vectors and rejections, sealed store layout with pairwise secrets, independent opens, commit fault injection, seed atomicity, migration retry, directory syncs at open, and the replay policy in the runtime; FFI restart, two-handle, session-frame, concurrent first opens, and a nonempty legacy roster whose v2 floor a session raises from 1 to 2 across restart; JNI `verifySealedGroupState`; Android instrumentation and Swift `swift test` group flows across restart, legacy migration with a corrupt leftover, and concurrent first opens.

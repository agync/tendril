---
type: Log Entry
title: "groups: commit pairwise secrets only on the initiator's kept path"
description: "A responder now persists the exported secrets of a bootstrap-admitted sibling session only after the initiator's first frame authenticates, so a path the initiator discarded is never persisted."
tags: [log, update]
kind: Update
status: stable
---

groups: commit pairwise secrets only on the initiator's kept path:

- **Fix (`crates/tendril-runtime/src/group.rs`):** an initiator racing several paths keeps one session and never writes on the others, but the responder used to install and persist every session that delivered `msg3`. A late discarded path could replace the kept link and overwrite the agreed pairwise secret. The responder now holds a Wire v2 session admitted under `pair_bootstrap` unpublished, unpersisted, and silent until the first transport frame after `Established` authenticates and is not `0x07 CLOSE` (the implicit commit). CLOSE, EOF, an error, pool close, or `BOOTSTRAP_COMMIT_TIMEOUT` (10 s) drop it without persisting, and the install checks for close under the state lock it holds through persistence and publication, so a close racing the commit leaves nothing behind; at most `MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER` (2) sessions of one peer and `MAX_PENDING_BOOTSTRAP_COMMITS` (32) in all wait per pool, and a session over either bound is refused, so one member cannot starve the others. No frame or wire change.
- **Fresh admission:** a bootstrap-admitted session, on either end, is refused with `stale bootstrap secret` when the `pair_bootstrap` that admitted it is no longer the current-`seq` one, both before and after persistence.
- **Driver (`crates/tendril-runtime/src/v2_driver.rs`):** a write-free seam reads and unseals one frame and stages it; the next read handles the staged frame first, so PONG, grants, and events follow the install in order.
- **Spec (`spec/groups-v1.md` Section 8):** the pairwise agreement rules define the commit, its bounds, and the non-atomic residual case; the multipath known limitation is replaced by a compatibility note.
- **Design (`docs/design/groups.md`):** bootstrap row, two new bounds, and the "Non-atomic commit" limitation.
- **Tests:** latch-driven unit tests for PING, cover, DATA, and REKEY-then-DATA commits, CLOSE, EOF, timeout, a first frame failing authentication, pool close before the frame and between the frame and the install, the pending caps (pool-wide and per peer), rotation before commit and after persistence, and simultaneous first contact; `responder_commits_only_the_path_the_initiator_kept` in `crates/tendril-runtime/tests/group_mesh.rs` replays a discarded path's `msg3`.

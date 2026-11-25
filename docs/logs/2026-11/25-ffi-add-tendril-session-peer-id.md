---
type: Log Entry
title: "ffi: add tendril_session_peer_id and binding session peer accessors"
description: "Expose the Noise-authenticated roster peer identifier on established v1 and v2 sessions across the C ABI and host-language bindings."
tags: [log, update]
kind: Update
status: stable
---

ffi: add tendril_session_peer_id and binding session peer accessors:

- Added `tendril_session_peer_id` to `crates/tendril-ffi/include/tendril.h` and `crates/tendril-ffi/src/lib.rs`, returning the Noise-authenticated canonical peer `device_id` on accepted responder sessions and the pinned `target_host_id` on initiated sessions without blocking parked `tendril_session_poll_event` calls.
- Exposed thin session accessors across host bindings: `Session.PeerID()` in Go, `Session.peer_id` in Python, `Session.peerId` in Node.js (and `bindings/node/index.d.ts`), `TendrilSession.peerId()` in Swift, and `TendrilSession.peerId()` (`TendrilNative.sessionPeerId`) in Kotlin JNI.
- Updated `docs/reference/ffi-and-bindings.md` and `docs/reference/web-and-mobile.md`.

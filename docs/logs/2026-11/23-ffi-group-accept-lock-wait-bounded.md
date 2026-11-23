---
type: Log Entry
title: "ffi: group accept lock wait bounded by caller deadline"
description: "Once groups run, tendril_session_accept and tendril_session_accept_v2 apply timeout_ms to the receiver lock wait as well as the dequeue."
tags: [log, update]
kind: Update
status: stable
---

ffi: group accept lock wait bounded by caller deadline:

- **Fix (`crates/tendril-ffi`):** In both group branches the receiver mutex was awaited outside any timeout, so a second concurrent accept with a short `timeout_ms` waited for the first caller's whole remaining timeout. One helper now bounds the lock wait and the dequeue by a single absolute deadline. C ABI signatures and error strings are unchanged, and an immediately available (uncontended) session is still returned at zero budget.
- **Reference (`docs/reference/ffi-and-bindings.md`):** State the deadline boundary: `timeout_ms` covers the wait for a group-routed session, including waiting behind another accept; a call parked on the router when the first group opened completes its dequeued stream's handshake under the pre-auth timeouts, outside `timeout_ms`.

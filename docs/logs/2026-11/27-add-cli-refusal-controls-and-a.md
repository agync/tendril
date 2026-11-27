---
type: Log Entry
title: "Add CLI refusal controls and a serve session_refused event"
description: "refusal-policy and clear-refusal-notice commands, a router refusal state, and a session_refused JSON line on tendril serve."
tags: [log, update]
kind: Update
status: stable
---

Add CLI refusal controls and a `session_refused` serve event. `tendril refusal-policy` shows or sets the host refusal policy and `tendril clear-refusal-notice` drops a recorded notice. `InboundRouter::with_refusal_state` installs one `RefusalState` on every limiter, and `tendril serve` uses it to print one `session_refused` JSON line per sent refusal. `SessionCloseCode` gains `INTERNAL_ERROR` (1011). The Kotlin JNI layer matches the `refused` code exactly, and Go documents and tests `ConnectWithOptions` refusals.

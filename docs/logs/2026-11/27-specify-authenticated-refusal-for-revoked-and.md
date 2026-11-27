---
type: Log Entry
title: "Specify authenticated refusal for revoked and pending peers"
description: "Close codes 4001 and 4004 on Wire v1, a sealed refusal at msg2 on Wire v2, and refusal notices."
tags: [log, update]
kind: Update
status: stable
---

Specify authenticated refusal. A Wire v1 host checks the wire floor first, then tells a revoked or pending device with one encrypted `CLOSE` (`4001 peer_revoked`, `4004 peer_pending`); strangers still get a silent drop. A Wire v2 host answers `msg1` with a refusal sealed under the pair secret, the same size and timing as a decoy, using its own replay cache and a per-peer limiter. Revocations record a 30-day notice by default, fork revocations never do, group listeners never refuse, and a revoked key is never re-admitted. New close code registry in `spec/wire-v1.md` Section 5.4 and conformance cases in `spec/conformance.md` Section 4; the vectors land with the implementation.

---
type: Log Entry
title: "Implement authenticated refusal in the core"
description: "Refusal notices and policy in the roster, CLOSE 4001 and 4004 on Wire v1, the sealed msg2 refusal on Wire v2, and the refusal vectors."
tags: [log, update]
kind: Update
status: stable
---

Implement authenticated refusal in `tendril-core`. The roster records refusal notices on revocation and stores the refusal policy with the roster. The Wire v1 responder checks the wire floor first, then sends one encrypted `CLOSE` with `4001` or `4004`. The Wire v2 responder classifies every entry for `msg1`, merges matches in a fixed order with the identity collision rule, and seals a refusal of decoy size under the pair secret, with its own replay cache and the shared limiter; a state change before `msg3` is refused after establishment under the session padding. Adds the `session_refusal_v1` and `v2_refusal` vectors and their Go verifier checks. A listener refuses only when it is built with `RefusalMode::Enabled`; the runtime wiring follows.

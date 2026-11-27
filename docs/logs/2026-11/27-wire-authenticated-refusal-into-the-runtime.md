---
type: Log Entry
title: "Wire authenticated refusal into the runtime listeners"
description: "Ordinary listeners refuse known revoked and pending peers, the Wire v1 close drains in the background, groups never refuse, initiators map the refusal, and tendril revoke records a notice."
tags: [log, update]
kind: Update
status: stable
---

Wire authenticated refusal into `tendril-runtime`. A `RefusalState` holds one refusal limiter, one refused-`msg1` replay cache, the drain bound and the audit sink for the whole endpoint; the router, the `V2ResponderState` and every `PreAuthRateLimiter` can share it. An ordinary Wire v1 or Wire v2 `accept` refuses a known revoked or pending peer; a group pool, standalone group listener or group mailbox never does, and the group hub refuses only ordinary roster peers.

A Wire v1 refusal writes its `CLOSE` frame, releases the half-open slot, half-closes the stream and drains it for up to `250 ms` in a background task, with at most `8` drains at once, so the accept loop never waits on a refused peer. A Wire v2 refusal at `msg2` keeps the decoy path, and one at `msg3` follows the Wire v1 close sequence. The `session_refused` audit record is emitted only when a refusal was sent. Initiators wrap a peer close so a refusal code gives `RuntimeError::refusal()`, and a Wire v1 connect still does not wait for a post-`msg3` frame. Expired refusal notices are pruned whenever the roster is loaded or saved, and `tendril revoke` records a notice per the roster policy unless `--no-notify` is given.

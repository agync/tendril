---
type: Log Entry
title: "web: group audit events coalesce and keep the control reserve free"
description: "TendrilWebGroup queues peer-triggered audits only below the app-data threshold and coalesces them per sender, outcome, and cap, so control events always have room."
tags: [log, update]
kind: Update
status: stable
---

web: group audit events coalesce and keep the control reserve free:

- **Fix (`bindings/web/src/group.js`):** Audit events caused by a peer's inbound frames could fill the 64-slot reserve kept for `manifest_updated`, `member_joined`, and `member_revoked`, so a flooding peer could hide a later revocation from `pollEvent`. Audits now queue only below the app-data threshold and are coalesced per authenticated sender, outcome (allow or deny), and cap. A queued entry holds the latest audit in full plus a `count`, a denial is never merged into an allow, and one sender holds at most 8 distinct queued entries. Listeners still see every audit. Authorization was never affected: WASM checks every inbound frame.
- **Types (`bindings/web/index.d.ts`):** queued audit events carry `count`.
- **Tests:** `bindings/web/test/group.test.mjs` covers floods, the threshold, coalescing, reentrant listeners, and close from a listener, and now runs in `make bindings/web`.
- **Reference (`docs/reference/web-and-mobile.md`):** documents the queueing rules.

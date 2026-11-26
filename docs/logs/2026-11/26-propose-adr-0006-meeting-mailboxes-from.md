---
type: Log Entry
title: "Propose ADR 0006 meeting mailboxes from a shared secret"
description: "Propose ADR 0006 meeting mailboxes from a shared secret"
tags: [log, update]
kind: Update
status: stable
---

Propose ADR 0006 meeting mailboxes from a shared secret

- [ADR 0006](../../adr/0006-meeting-mailboxes.md), status Proposed: a relay mailbox key derived from a `Remote3Group` code with `Argon2id`, salted by the canonical relay host and a 15-minute epoch, so a relay cannot precompute guesses or batch them across epochs.
- Tier 1 allowlist relays would admit meeting registrations through opt-in delegated `RelayTicket`s (unchanged bytes) from an allowlisted host key, for a concrete key only, with one stream per registration, a per-issuer admission window, and teardown at the ticket deadline.
- Pairing over a meeting mailbox is PAKE only and relies on the pending host store and the relay's `replaced` signal. The QR stays the pairing URI. No spec or code changes yet.

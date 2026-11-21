---
type: Log Entry
title: "Add Wire v2 privacy profile, WakeProvider, and mobile SDK verification"
description: "Add Wire v2 privacy profile, WakeProvider, and mobile SDK verification"
tags: [log, update]
kind: Update
status: stable
---

Add Wire v2 privacy profile, WakeProvider, and mobile SDK verification.

- Documented [Wire v2 privacy profile and PAKE](../../design/wire-v2-privacy.md) covering `0x02` preamble binding, `min_wire_version` anti-downgrade, pseudonymous paired reconnect, opt-in `Argon2id` PAKE pairing, blinded `/v2/relay` mailboxes, bucketed `0x09 PADDED`/`0x08 PADDING` frames, and jittered keepalive/rekey scheduling.
- Linked [Optional push wake providers](../../design/wake-providers.md) and [Wire v2 privacy profile and PAKE](../../design/wire-v2-privacy.md) in [the design index](../../design/index.md).
- Updated [ADR 0003](../../adr/0003-v2-privacy-profile.md) to `stable` (accepted) and indexed `wire-v2.md` and `relay-v2.md` in `spec/README.md`.
- Added `/v2/relay` and async Wire v2 runtime drivers, alongside Android Gradle AAR and macOS Swift 6.4 SDK verification.
- Added the no-feature `cargo test -p tendril-core --test v2_privacy` run to `Makefile`.

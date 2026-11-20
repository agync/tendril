---
type: Log Entry
title: "Add six-rung path providers, iroh P2P, and embedded relay"
description: "Add six-rung path providers, iroh P2P, and embedded relay"
tags: [log, update]
kind: Update
status: stable
---

Added `EmbeddedRelay`, the `overlay` (host tailnet and `0o600` scoped helper IPC), `p2p` (`iroh` 1.5 behind `p2p-iroh`), and `broker` (`broker+ws://` / `broker+wss://`) providers in `tendril-runtime`, `Roster::update_relay_hints` zero-re-pair migration in `tendril-core`, and corresponding flags/dial routes in `tendril-cli`. See [Six-rung path providers and relay ladder](../../design/providers-and-relay-ladder.md).

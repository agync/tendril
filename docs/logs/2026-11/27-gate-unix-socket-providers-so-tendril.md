---
type: Log Entry
title: "Gate Unix-socket providers so tendril-runtime builds on Windows"
description: "Gate Unix-socket providers so tendril-runtime builds on Windows"
tags: [log, update]
kind: Update
status: stable
---

Gate Unix-socket providers so tendril-runtime builds on Windows

Gate the `local` provider and the overlay helper to Unix targets, and drop the `cfg(not(unix))` socket-binding fallback that called `tokio::net::UnixListener::bind` where that type does not exist. `LocalDialer` stays in the API on every target and reports that the provider requires Unix domain sockets, while `LocalListener`, `OverlayHelperDialer`, and `OverlayHelperListener` are Unix-only exports. `select_overlay_mode` resolves helper modes to unavailable without Unix sockets. CI now compiles `tendril-runtime` on `windows-2022`.

Updated [CI, releases, and registry publishing](../../contribution/release.md) and [Providers and the relay ladder](../../design/providers-and-relay-ladder.md).

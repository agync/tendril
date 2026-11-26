---
type: Log Entry
title: "swift: tighten route tests and bindings docs"
description: "Prove relayHost reaches the dialer, widen the routes.json replay gate, and update the Swift binding docs."
tags: [log, update]
kind: Update
status: stable
---

swift: tighten route tests and bindings docs

The `relayHost` test now asserts the core relay-mode parser error and dials a local P2P listener with `relayHost: "disabled"`. The `routes.json` replay runs wherever CryptoKit and Security exist, and its guards also require disjoint covered and skipped sets. `configureP2p` tests cover kept keys across calls and across `configureTransportsJSON`. The [FFI and bindings reference](../../reference/ffi-and-bindings.md) lists `relayHost:` in the Swift `connectWithOptions` signature, `configureP2p` next to `configureRoutes`, and the Swift `routes.json` replay with its `route_set` skip. The [Web and mobile bindings](../../reference/web-and-mobile.md) test count is current.

---
type: Log Entry
title: "swift: add configureP2p for port mapping and bind addresses"
description: "Add TendrilEndpoint.configureP2p for p2p_port_mapping and p2p_bind_addrs, and extend the Swift route tests."
tags: [log, update]
kind: Update
status: stable
---

swift: add configureP2p for port mapping and bind addresses

Add `TendrilEndpoint.configureP2p(portMapping:bindAddrs:)`, which merges `p2p_port_mapping` and `p2p_bind_addrs` into the last transport configuration like `configureRoutes`, and update the [FFI and bindings reference](../../reference/ffi-and-bindings.md#transport-keys) and [Web and mobile bindings](../../reference/web-and-mobile.md). Swift tests cover the `routes_reason` pairing result, `relayHost` on `connectWithOptions`, the `NOT_FOUND` error for an unknown peer, and a replay of `spec/vectors/routes.json`.

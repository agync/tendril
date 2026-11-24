---
type: Log Entry
title: "swift: pairing URIs, endpoint-free connect and route refresh"
description: "The Swift package wraps the pairing URI and route C calls, connects over stored routes, and refreshes host routes from NWPathMonitor updates."
tags: [log, update]
kind: Update
status: stable
---

swift: pairing URIs, endpoint-free connect and route refresh:

**Behaviour change for existing Swift apps:** `TendrilEndpoint.connect` and `connectV2` take an optional `endpoint`. Without one they dial the peer's stored routes; a non-empty endpoint is an explicit operator endpoint, dialed alone. Existing calls that pass an endpoint compile unchanged.

- **New calls (`bindings/swift/Sources/Tendril/Tendril.swift`):** `issuePairingUri`, `pairUri`, `pairV2Uri` (with `routePolicy`, `saveRoute`, `endpoint`, `code`), `connectWithOptions` (recovery URI, `replaceRoutes`, `routePolicy`, `wire`), `setPeerRoutes`, `peerRoutes`, `clearPeerRoutes`, `applyRouteUri`, `refreshRoutes` and `configureRoutes` (`advertisedEndpoints`, `relayAuthOrigins`, `advertise`, `routePolicy`, `signRoutes`). Results are the C ABI's JSON strings, as for the existing calls.
- **Route refresh:** `startPathMonitoring` runs an `NWPathMonitor` that calls `refreshRoutes()` on each path update, so a host's announced route set follows its network; `stopPathMonitoring` and `close` stop it. The first refresh makes the endpoint a route host, so only hosts start it.
- **Tests (`bindings/swift/Tests/TendrilTests/TendrilConformanceTests.swift`):** signed URI pairing that persists every route and connects without an endpoint, on Wire v1 and v2; issue and pair options; the route setter, view and clear; offline application; recovery-URI connects; a refresh that delivers a route set to a live session, then reconnects over the new route; the path-update hook; a multi-network snapshot that advertises LAN and overlay addresses and not a cellular CGNAT one; route configuration keys; a sealed host that keeps its route sequence across restart; and a scanner passthrough that renders the URI with `CIQRCodeGenerator` (level M), decodes it with Vision and pairs from the decoded string with a verified route check.
- **See also:** [pairing: multi-route URIs, signed routes and automatic fallback](23-pairing-multi-route-uris-signed-routes.md) for the feature as a whole.

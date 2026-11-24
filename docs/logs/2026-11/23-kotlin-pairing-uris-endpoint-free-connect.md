---
type: Log Entry
title: "kotlin: pairing URIs, endpoint-free connect and the multi-network snapshot"
description: "The Android binding wraps the pairing URI and route C ABI, connects over stored routes with a null endpoint, and feeds hosts a complete multi-network snapshot from the foreground service."
tags: [log, update]
kind: Update
status: stable
---

kotlin: pairing URIs, endpoint-free connect and the multi-network snapshot:

**Behaviour change for existing Kotlin apps:** `TendrilEndpoint.connect` and `connectV2` accept a null or empty `endpoint`, which dials the peer's stored routes. A non-empty endpoint is an explicit operator endpoint, as before.

- **JNI and wrappers (`bindings/kotlin/jni/tendril_jni.c`, `TendrilNative.java`, `TendrilClient.kt`):** `issuePairingUri`, `pairUri`, `pairV2Uri`, `connectWithOptions` (recovery URI, `replaceRoutes`, route policy), `setPeerRoutes`, `peerRoutes`, `clearPeerRoutes`, `applyRouteUri`, `refreshRoutes` and `configureRoutes` (`advertisedEndpoints`, `relayAuthOrigins`, `advertise`, `routePolicy`, `signRoutes`). Pairing URIs and options are zeroized after the call.
- **Multi-network snapshot (`TendrilForegroundService.kt`):** an all-networks callback (VPN networks included) keeps a map of `Network` to `LinkProperties` and `NetworkCapabilities`. `LocalBinder.attachEndpoint` seeds it from `ConnectivityManager.allNetworks` before the first issuance, every change passes the whole map to `refreshRoutes`, and a 60 s timer calls `refreshRoutes(null)` so the runtime reuses the retained snapshot. The runtime owns the 30 s empty-snapshot debounce.
- **Hardening:** `connectWithOptions` embeds `grantJson` only when it is exactly one strictly valid JSON object (blank means no grant), `configureRoutes` merges into the last full transport configuration instead of replacing it, the foreground service registers its all-networks callback before seeding and serializes seeding with callbacks, `onDestroy` guards each teardown step, the cached transport configuration (secrets included) is cleared on close, and attaching an endpoint never sends an empty snapshot when enumeration was unavailable.
- **Docs:** `docs/reference/web-and-mobile.md` describes the new surface and the instrumentation suite.
- **Tests:** `TendrilJniConformanceTest.verifyPairingUriRoutes` repeats the flow on the host JVM (Wire v1 and v2 URI pairing, endpoint-free connect, setter, offline apply, recovery, snapshot refresh with a delivered route set, sealed sequence across reopen). `TendrilAndroidSmokeTest` adds `signedPairingPersistsAllRoutes`, `networkCallbackRefreshesRoutes`, `multiNetworkSnapshot`, `addressChangePropagatesAndReconnects`, `sealedSeqSurvivesRestart`, `builderUriIsUriParseFixpoint`, `scannerPassthrough` (ZXing at ECC M, ML Kit decode, byte equality, verified route check) and `serviceSeedsHostFromRealNetworks`. The ZXing and ML Kit dependencies are `androidTest` only.

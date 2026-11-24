---
type: Log Entry
title: "pairing: multi-route URIs, signed routes and automatic fallback"
description: "One host-signed pairing URI carries LAN, overlay and relay routes. Clients store them, fall back between them on later connects without an endpoint, and follow the host's address changes through signed route updates."
tags: [log, update]
kind: Update
status: stable
---

pairing: multi-route URIs, signed routes and automatic fallback:

**Behaviour change:** hosts sign their pairing URIs, `pair` stores every route of a URI whose signature verifies, and `connect` and `dial` use stored routes when given no endpoint. `tendril pair --pairing-uri` used to save every hint in the URI to the roster (`relay_hints`) on both wires, without dialing them later. A URI without a valid host signature saves no route by default: `--save-route` saves only the route that carried the pairing, and `--endpoint` saves that endpoint. Hints saved by earlier versions stay in `relay_hints` as display data and are not migrated into dialable routes: re-pair with a fresh URI, apply one with `tendril route apply`, or pass `--endpoint`.

- **Defaults:** SDK and FFI hosts advertise LAN and overlay addresses (`advertise: auto`) and sign every URI. Clients keep every signed route (`allSigned`). The CLI advertises only concrete binds and `--advertise-endpoint`. A client that scans once reaches the host on the LAN, over a VPN overlay, and through a relay, in that order, with no prompt.
- **Protocol:** pairing URIs gain `rp` (relay key, checked against the authenticated host key before `msg3`), `rq` (route sequence) and `rs` (Ed25519 route statement over every earlier byte). A signed route set travels in the new `0x0C ROUTE_SET` frame, hybrid-signed with a persistent sequence, sent only to clients that opt in through `SessionHello.route_seq`. See `spec/pairing-v1.md` Section 6, `spec/wire-v1.md` Section 5.2 and `spec/vectors/routes.json`.
- **Route policy:** `allSigned` (default), `committedOnly` and `none` on the CLI (`--route-policy`, `--save-route`) and every binding. Stored routes carry a source (`operator`, `signed`, `committed`) and the sequence never decreases.
- **Relay credentials:** admission material is attached only to origins configured in `relay_auth_origins` (`--relay-auth-origin`) or to the explicit endpoint of a call.
- **Removed and tightened:** `tendril pair --relay-v2` is rejected, because `/v2/relay` is never used for pairing. Iroh pairing hints no longer use Pkarr or DNS lookup. URI hints pass an egress policy and a code-kind guard before any dial.
- **CLI:** `serve --advertise-endpoint`, `--issue-code auto`, `--no-route-signature`; `pair --route-policy`, `--save-route`, `--relay-auth-origin`; `dial` without `--endpoint`, with `--pairing-uri` and `--replace-routes`; `tendril route set|list|clear|apply`.
- **Bindings:** Go, Python, Node, Swift, Kotlin, the C ABI and the browser SDK wrap issuing, URI pairing, endpoint-free connect, recovery URIs, the route setter and offline apply. The per-binding entries are [ffi](23-ffi-pairing-uris-endpoint-free-connect.md), [swift](23-swift-pairing-uris-endpoint-free-connect.md) and [kotlin](23-kotlin-pairing-uris-endpoint-free-connect.md).
- **Docs:** new guide [Seamless pairing defaults](../../usage/seamless-pairing.md); updated [Wire protocol and pairing](../../design/wire-and-pairing.md), [Six-rung path providers and relay ladder](../../design/providers-and-relay-ladder.md), [Sans-I/O core state machines and path policy](../../design/sans-io-core.md), [FFI ABI and cross-language bindings](../../reference/ffi-and-bindings.md) (per-language route surface), [Web and mobile bindings](../../reference/web-and-mobile.md), [Conformance vectors](../../reference/conformance-vectors.md) and [Reference CLI, relay deployment, and conformance peer](../../usage/cli-demo.md).

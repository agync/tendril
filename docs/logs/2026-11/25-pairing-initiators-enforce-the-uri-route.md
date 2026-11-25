---
type: Log Entry
title: "pairing: core initiators enforce the URI route checks before msg3"
description: "Move the rp, operator relay key and route statement checks of pairing into the v1 and v2 PAKE initiators, and tighten three parse-time hint rules."
tags: [log, update]
kind: Update
status: stable
---

pairing: core initiators enforce the URI route checks before msg3:

- Added `PairRouteBinding` and `PairRouteVerdict` to `tendril_core::pairing`. `PairingInitiator` and `V2PakePairInitiator` take a binding (`with_route_binding`, `with_pairing_uri`, `set_route_binding` before `msg2`), expose `route_verdict()` from `msg2` on, enforce the bound URI's host pin (a different pinned host is refused), and refuse `msg3` on a failed `rp`, operator key or route statement check, deferred or not. A refusal closes the initiator.
- The runtime pairing drivers and the WASM pairing initiators read the core verdict instead of repeating the checks. A WASM initiator with a pairing URI and no deferred claim no longer writes `msg3` past a failed check.
- Pairing hint validation unwraps every fixed IPv4 embedding before the blocked-address check and blocks local-use NAT64 and Teredo addresses, a `Lan2Group` URI rejects `direct:` and bare hints that are not loopback or LAN IP literals, and a Wire v2 session initiator with padding disabled omits `SessionHello.route_seq`.
- Added the `pairing_route_check` cases to `spec/vectors/routes.json`, replayed on both wires in Rust and recomputed in Go.
- Updated `spec/pairing-v1.md` Sections 6.2, 6.3 and 6.5, `spec/wire-v1.md` Section 5.2 and `docs/design/sans-io-core.md`.

---
type: Log Entry
title: "Add HKDF P2P identity, PeerID rate limit, and browser/FFI iroh"
description: "Add deterministic HKDF P2P identity keys, PeerID-scoped pre-auth rate limiting, FFI/SDK P2P serving, and opt-in browser WASM iroh transport."
tags: [log, update]
kind: Update
status: stable
---

Add HKDF P2P identity, PeerID rate limit, and browser/FFI iroh:

- Added RFC 5869 `hkdf_sha256_32` and `EndpointIdentity::derive_p2p_identity_seed` (`tendril/p2p/iroh-identity/v1`) in `crates/tendril-core` so host `P2pListener` identities survive restarts deterministically and rotate with the static Noise key.
- Added `PathStream::peer_transport_id()` and `PreAuthRateLimiter::try_acquire_for_peer` in `crates/tendril-runtime` so inbound P2P pre-auth handshakes rate-limit by transport PeerID rather than starving peers sharing a relay IP, unified `dial_endpoint`, and closed `iroh` client endpoints cleanly before runtime teardown.
- Wired `p2p-iroh` into `crates/tendril-ffi` (`tendril_endpoint_serve_p2p`), Go (`ServeP2p`), Python (`serve_p2p`), Node (`serveP2p`), Kotlin (`serveP2p`), and Swift (`serveP2p`).
- Added opt-in `p2p-iroh` browser transport (`crates/tendril-wasm`, `bindings/web/pkg-p2p`, `bindings/web/src/iroh.js`, and demo `iroh://` support) enabling browser-to-host pairing and sessions over n0 public WebSocket relays without a self-hosted relay.

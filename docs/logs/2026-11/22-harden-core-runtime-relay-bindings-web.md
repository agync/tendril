---
type: Log Entry
title: "Harden core, runtime, relay, bindings, web, and CI"
description: "Synchronize docs and specs with security and privacy remediations across core, relay, runtime, bindings, web, and CI."
tags: [log, update]
kind: Update
status: stable
---

Harden core, runtime, relay, bindings, web, and CI:

- **Core (`tendril-core`):** Enforce `MAX_LIVE_PAIRING_CODES = 4`, bucketed PAKE `msg3` (`PairClaim`) and `PairResponse` (`Success` and `Error`) padding (`V2_HANDSHAKE_BUCKETS`), canonical CRL ID matching, v1 wire floor gating, single-epoch scoped `/v2/relay` tickets (`mint_v2_epoch_relay_ticket`, `spans_multiple_v2_epochs`), and `poly1305` zeroization.
- **Relay & CLI (`tendril-relay`, `tendril-cli`):** Remove the redundant relay crate Containerfile in favor of the root `Containerfile`, add `--trusted-proxy-header` (`xff` default vs `forwarded`) and pre-upgrade semaphore/timeout behind `--trusted-proxy`, enforce `0600` regular non-symlink checks on `tendril-relay` (`--auth-secret-file`, `--tls-key`) and `tendril` CLI (`--code-file`, `--token-file`, `--grant @path`, `--relay-auth-secret-file`, `--relay-ticket-file`, `--p2p-relay-token-file`, `--p2p-api-secret-file`, `--wake-secret-file`), and bind `/v2/relay` listeners in `tendril serve` (`sync_v2_relay_listeners`) only for `PeerState::Active` peers with staggered bind jitter.
- **Runtime (`tendril-runtime`):** Add CSPRNG-jittered reconnect backoffs and `22.5s..=37.5s` control pings in `RelayV2Listener`, pin relay DNS, isolate `?relay=` URI hints via `P2pOptions::for_endpoint`, and canonicalize relay hosts via `canonical_relay_host`.
- **Web, WASM, & Bindings (`tendril-wasm`, `bindings/web`, mobile, CI):** Add `WasmV2SessionInitiator::send_ping` / `TendrilWebSession.ping()`, `onPersistRosterBytes`, `createIndexedDbVault` / `openTendrilVault`, `?relay=` isolation in `dialIrohStream`, fragment-only `#code=` / `#uri=` demo secrets with log redaction on by default, JNI/Keychain memory zeroization, and hash-pinned CI workflows.

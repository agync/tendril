---
type: Log Entry
title: "web: Happy Eyeballs dialing, /v2/relay priority, and broker+ws(s)"
description: "Add canonical /v2/relay priority and next_deadline_ms() to PathPlanner, expose WasmPathPlanner and broker+ws(s):// browser dialing, and use Happy Eyeballs multi-route fallback in @tendril-sdk/web."
tags: [log, update]
kind: Update
status: stable
---

# web: Happy Eyeballs dialing, /v2/relay priority, and broker+ws(s)

- Added `sort_key`, `sort_candidates`, and `PathPlanner::next_deadline_ms` in `crates/tendril-core/src/policy.rs` so `/v2/relay` precedes `/v1/relay` ahead of numeric-host and tie-breaker ordering. See [Sans-I/O core state machines and path policy](../../design/sans-io-core.md).
- Exposed `WasmPathPlanner`, `allow_insecure_ws`, and `ProviderId::Broker` candidate admission in `crates/tendril-wasm/src/lib.rs`, and added `serve_broker` to `tendril-conformance-peer`.
- Added `dialBrokerStream`, `AbortSignal` support across relay/broker/P2P dialers, and a shared `WasmPathPlanner`-driven Happy Eyeballs runner for Wire v1 `pair` and Day-2 `connect` / `connectV2` in `@tendril-sdk/web` while keeping `pairV2` sequential. See [Six-rung path providers and relay ladder](../../design/providers-and-relay-ladder.md) and [Web and mobile bindings](../../reference/web-and-mobile.md).

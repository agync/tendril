---
type: Log Entry
title: "Exclude cold WASM load from iroh timeout and record phone P2P baseline"
description: "Exclude cold WASM load from iroh timeout and record phone P2P baseline"
tags: [log, update]
kind: Update
status: stable
---

# Exclude cold WASM load from iroh timeout and record phone P2P baseline

- Warmed `initTendrilP2p()` before starting `timeoutMs` in `TendrilWebClient.pair` and `TendrilWebClient.connect`, and ensured `WasmPairInitiator`/`WasmSessionClient` handles free cleanly if `dialWebStream` throws (`bindings/web/src/index.js`).
- Added `node:zlib` gzip compression for static assets (`.wasm`, `.js`, `.mjs`, `.html`, `.css`, `.json`) in `bindings/web/demo/server.mjs` and updated the reconnect log label for `iroh://` targets in `bindings/web/demo/app.js`.
- Recorded physical phone zero-setup `iroh://` Gate #9 timings (`0.87 s` warm pair, `634.9 ms` Noise XX QUIC establish, `63-69 ms` `PING`/`PONG` RTT, `392.9 ms` reconnect) in `docs/reference/web-and-mobile.md`.

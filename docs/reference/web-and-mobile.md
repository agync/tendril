---
type: Reference
title: Web and mobile bindings
description: Browser WASM SDK, demo application, Android Kotlin JNI wrapper, Swift SPM package, and Gate #7/#8 measurements.
status: stable
tags: [reference, wasm, web, mobile, bindings]
---

# Web and mobile bindings

Browser and mobile targets run the same Rust protocol core as desktop targets. Browsers execute a sans-I/O WebAssembly build over `WebSocket`, while Android and Apple targets call `crates/tendril-ffi` (`tendril.h`) with platform keychain and network-transition integration.

## Architecture across targets

| Target | Bridge Crate / Layer | Transport Path | Secure Storage & Platform Integration |
|---|---|---|---|
| Browser (`bindings/web`) | `crates/tendril-wasm` (`#![forbid(unsafe_code)]`, `wasm-bindgen = "=0.2.130"`, opt-in `p2p-iroh` feature) | Browser `WebSocket` (`spec/relay-v1.md`) and opt-in `iroh` over `ws_stream_wasm` + `n0_dns` | `TendrilWebClient`, `dialIrohStream`, `computeCodeMacWorker` Web Worker Argon2 offload |
| Android (`bindings/kotlin`) | JNI C shim (`bindings/kotlin/jni/tendril_jni.c`) -> `libtendril_ffi.so` | Rust `P2pListener` / `RelayDialer` / `DirectDialer` (`serveP2p` via `p2p-iroh`) | `KeystoreStateCipher` (`AndroidKeyStore` AES-256-GCM), `TendrilForegroundService` (`NetworkCallback`) |
| Apple (`bindings/swift`) | SwiftPM C target (`CTendril`) -> `libtendril_ffi` | Rust `P2pListener` / `RelayDialer` / `DirectDialer` (`serveP2p` via `p2p-iroh`) | `TendrilKeychainStore` (`Security` Keychain + `CryptoKit` AES-GCM) |

## WebAssembly core and browser SDK

### `crates/tendril-wasm`

`crates/tendril-wasm` compiles cleanly for `wasm32-unknown-unknown` using `.cargo/config.toml` (`getrandom_backend="wasm_js"`). Its default build (`bindings/web/pkg`) remains strictly sans-I/O and exports four stateful types plus eight helper functions; enabling the opt-in `p2p-iroh` feature (`bindings/web/pkg-p2p`) adds `WasmIrohStream` and `parse_p2p_endpoint_json` over `iroh` 1.5 (`ws_stream_wasm` + `ring`):

- `WasmIdentity`: generates, exports, and restores client Ed25519 signing and X25519 static keys without touching host storage directly.
- `WasmRoster`: serializes pinned hosts, pairing state, and verified CRL sequence tracking.
- `WasmPairInitiator`: sans-I/O `Intent::Pair` handshake state machine outputting raw wire frames (`start`, `feed_bytes`).
- `WasmSessionClient`: sans-I/O `Intent::Session` initiator supporting encrypted `send_data`, `send_ping`, `send_rekey`, `send_close`, `tick`, and `authorize`.
- Vector and verification helpers: `device_id`, `fingerprint_host`, `fingerprint_device`, `pairing_sas`, `compute_code_mac`, `verify_rotation_chain_json`, `verify_grant_json`, and `parse_pairing_uri_json`.
- Opt-in browser P2P (`p2p-iroh` feature): `WasmIrohStream` (`dial`, `send_chunk`, `recv_chunk`, `close`) and `parse_p2p_endpoint_json`.

### `@tendril/web` (`bindings/web`)

- `bindings/web/src/relay.js` implements the `spec/relay-v1.md` client WebSocket handshake (`challenge`, `dial`, `ready`) and binary frame bounds (`65,521` bytes max).
- `bindings/web/src/index.js` dynamically imports `./iroh.js`, which in turn lazily imports `bindings/web/pkg-p2p/` on demand when `iroh://` or opt-in P2P helpers (`initTendrilP2p`, `parseP2pEndpoint`, `dialIrohStream`) are used, keeping default page loads strictly on the sans-I/O bundle without fetching P2P WASM or glue assets.
- `bindings/web/src/worker.js` and `computeCodeMacWorker` move Argon2id pairing-code proof computation off the UI thread.
- `bindings/web/demo/` provides an interactive pairing/session web page supporting both `wss://.../v1/relay` and `iroh://...` endpoints (`?endpoint=iroh://...` or `demo-config.json`), plus a Node HTTP/WebSocket `/v1/relay` reverse-proxy server (`server.mjs`) with zero third-party npm runtime dependencies.
- `bindings/web/test/browser_e2e.mjs` runs all four helper `spec/vectors/` files, `parseP2pEndpoint` validation, and a live Noise handshake, encrypted data exchange, `rekey`, `ping`/`pong`, `authorize`, `revoke`, and `close` flow in headless Chrome against `tendril-relay` and `tendril-conformance-peer` (plus live `iroh://` browser-to-host E2E over n0 public relays when `TENDRIL_WEB_P2P_LIVE=1`).

## Android Kotlin JNI (`bindings/kotlin`)

- `bindings/kotlin/jni/tendril_jni.c` bridges `dev.tendril.TendrilNative` methods to `crates/tendril-ffi/include/tendril.h`, converts standard UTF-8 <-> UTF-16 directly (preserving non-BMP characters), validates non-negative integer inputs and `0..=65535` close codes, maps `TENDRIL_WOULD_BLOCK` and `TENDRIL_EOF` into JSON status sentinels, and frees all returned C strings with `tendril_string_free`.
- `TendrilEndpoint` and `TendrilSession` in `TendrilClient.kt` implement `java.io.Closeable` with `ReentrantReadWriteLock` / `ReentrantLock` handle synchronization so concurrent `close()` calls cannot race active FFI polls or sends.
- `KeystoreStateCipher.kt` provides a standalone AES-256-GCM sealing helper (`12`-byte random IV prefix) backed by a hardware `AndroidKeyStore` key; `TendrilEndpoint` itself delegates on-disk identity and roster storage inside `stateDir` to `tendril-ffi` `StateStore`.
- `TendrilForegroundService.kt` maintains a `dataSync` foreground notification and monitors `ConnectivityManager.registerDefaultNetworkCallback` across Wi-Fi and cellular handoffs.
- `bindings/kotlin/test/TendrilJniConformanceTest.java` validates all four helper vectors (`fingerprints.json`, `pairing_mac.json`, `rotation.json`, `grants.json`) and bidirectional live interop against `tendril-conformance-peer` on host Linux JVM (`make bindings/jni` tests the C JNI bridge and Java declarations; compiling `.kt` Android sources requires Gradle and the Android SDK).

## Apple Swift (`bindings/swift`)

- `bindings/swift/Package.swift` declares `CTendril` (`module.modulemap` + `shim.h` referencing `crates/tendril-ffi/include/tendril.h`), the synchronized `Tendril` wrapper module (`TendrilCrypto`, `TendrilEndpoint`, `TendrilSession`, including `serveDirect`, `serveRelay`, and `serveP2p`), `TendrilKeychainStore` (standalone Keychain + `CryptoKit` AES-GCM master-key sealing helper), and `TendrilTests` (offline vectors, fork rejection, and local endpoint lifecycle).
- Verification note: SwiftPM compilation and `XCTest` execution (`TendrilConformanceTests.swift`) require Apple macOS/iOS toolchains and were not executed on Linux.

## Gate #7 baselines

| Artifact | Target | Raw Size | Stripped / Compressed | Measurement Method |
|---|---|---|---|---|
| `bindings/web/pkg/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`, default sans-I/O) | 782,671 bytes (764.3 KiB) | 292,452 bytes (285.6 KiB) gzipped | `wasm-bindgen --target web` + `gzip -c -9` |
| `bindings/web/pkg-p2p/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`, `--features p2p-iroh`) | 4,116,121 bytes (3.93 MiB) | 1,519,232 bytes (1.45 MiB) gzipped | `wasm-bindgen --target web` (`p2p-iroh`) + `gzip -c -9` |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26, `--no-default-features`) | 3,434,576 bytes | 3,434,248 bytes (3.28 MiB) stripped | `stat -c%s` before and after `llvm-strip` |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26, default `p2p-iroh`) | 12,291,992 bytes | 12,291,664 bytes (11.72 MiB) stripped | `stat -c%s` before and after `llvm-strip` |
| `aarch64-apple-ios` static archive | `aarch64-apple-ios` | Not measured on Linux | Not measured on Linux | Requires Apple Xcode toolchain |

## Gate #8 WASM Argon2id timings

Measured via `benchmarkArgon2` (`t=3, m=64 MiB, p=1`) in headless desktop Google Chrome (`bindings/web/test/browser_e2e.mjs`) and on a physical mobile phone browser over TLS relay demo:

| Execution Context | Runs | Min (ms) | Median (ms) | Max (ms) | Notes |
|---|---|---|---|---|---|
| Desktop headless Chrome (main thread) | 3 | 158.6 | 159.4 | 163.9 | Single-call `compute_code_mac` (`useWorker: false`) |
| Desktop headless Chrome (Web Worker) | 2 | 168.7 | 193.8 | 193.8 | Includes worker spawn and WASM init (`useWorker: true`) |
| Mobile phone browser (main thread) | 3 | 153.8 | 155.8 | 171.7 | Physical phone run against hosted demo (`useWorker: false`) |
| Mobile phone browser (Web Worker) | 3 | 402.6 | 665.7 | 1030.9 | Includes worker spawn and WASM init per call (`useWorker: true`) |

## Gate #9 real-device relay pairing and reconnect baseline

Observed between a physical mobile browser and the desktop Rust `tendril` CLI host over the WebSocket relay demo (`< 30 s` pairing target):

- **Remote pairing:** `0.59 s` end-to-end with verified 16-character SAS match and host `tendril confirm`.
- **Authenticated session connect:** `332.1 ms` initial Noise XX handshake over relay (`164.5 ms` repeat connect).
- **Encrypted control and data round-trip:** `27 ms` encrypted `0x05 PING` -> `0x06 PONG`, followed by `0x04 REKEY` and verified plaintext delivery (`21` bytes) decoded on the Rust host.
- **Disconnect and reconnect recovery:** Re-established authenticated relay sessions in `526.5 ms`, `520.4 ms`, and `418.0 ms` across manual reconnect and connectivity restoration tests.

## Verification commands

```bash
make bindings/wasm      # Build sans-I/O release WASM and generate bindings/web/pkg
make bindings/wasm-p2p  # Build opt-in p2p-iroh WASM and generate bindings/web/pkg-p2p
make bindings/web       # Run headless Chrome vector + benchmark + live relay E2E suite
TENDRIL_WEB_P2P_LIVE=1 node bindings/web/test/browser_e2e.mjs  # Also run live bare iroh:// Chrome E2E
make bindings/jni       # Compile libtendril_jni.so and run JVM vector + interop tests
make bindings/android   # Cross-compile release libtendril_ffi.so for aarch64-linux-android
make bindings/check     # Run Go, Python, Node, Web WASM, and Kotlin JNI suites
```

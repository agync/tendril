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
| Browser (`bindings/web`) | `crates/tendril-wasm` (`#![forbid(unsafe_code)]`, `wasm-bindgen = "=0.2.130"`) | Browser `WebSocket` (`spec/relay-v1.md`) | `TendrilWebClient`, `computeCodeMacWorker` Web Worker Argon2 offload |
| Android (`bindings/kotlin`) | JNI C shim (`bindings/kotlin/jni/tendril_jni.c`) -> `libtendril_ffi.so` | Rust `RelayDialer` / `DirectDialer` | `KeystoreStateCipher` (`AndroidKeyStore` AES-256-GCM), `TendrilForegroundService` (`NetworkCallback`) |
| Apple (`bindings/swift`) | SwiftPM C target (`CTendril`) -> `libtendril_ffi` | Rust `RelayDialer` / `DirectDialer` | `TendrilKeychainStore` (`Security` Keychain + `CryptoKit` AES-GCM) |

## WebAssembly core and browser SDK

### `crates/tendril-wasm`

`crates/tendril-wasm` compiles cleanly for `wasm32-unknown-unknown` using `.cargo/config.toml` (`getrandom_backend="wasm_js"`) and exports four stateful types plus eight helper functions:

- `WasmIdentity`: generates, exports, and restores client Ed25519 signing and X25519 static keys without touching host storage directly.
- `WasmRoster`: serializes pinned hosts, pairing state, and verified CRL sequence tracking.
- `WasmPairInitiator`: sans-I/O `Intent::Pair` handshake state machine outputting raw wire frames (`start`, `feed_bytes`).
- `WasmSessionClient`: sans-I/O `Intent::Session` initiator supporting encrypted `send_data`, `send_ping`, `send_rekey`, `send_close`, `tick`, and `authorize`.
- Vector and verification helpers: `device_id`, `fingerprint_host`, `fingerprint_device`, `pairing_sas`, `compute_code_mac`, `verify_rotation_chain_json`, `verify_grant_json`, and `parse_pairing_uri_json`.

### `@tendril/web` (`bindings/web`)

- `bindings/web/src/relay.js` implements the `spec/relay-v1.md` client WebSocket handshake (`challenge`, `dial`, `ready`) and binary frame bounds (`65,521` bytes max).
- `bindings/web/src/worker.js` and `computeCodeMacWorker` move Argon2id pairing-code proof computation off the UI thread.
- `bindings/web/demo/` provides an interactive pairing/session web page and a Node HTTP/WebSocket `/v1/relay` reverse-proxy server (`server.mjs`) with zero third-party npm runtime dependencies.
- `bindings/web/test/browser_e2e.mjs` runs all four helper `spec/vectors/` files plus a full live Noise handshake, encrypted data exchange, `rekey`, `ping`/`pong`, `authorize`, `revoke`, and `close` flow in headless Chrome against `tendril-relay` and `tendril-conformance-peer`.

## Android Kotlin JNI (`bindings/kotlin`)

- `bindings/kotlin/jni/tendril_jni.c` bridges `dev.tendril.TendrilNative` methods to `crates/tendril-ffi/include/tendril.h`, converts standard UTF-8 <-> UTF-16 directly (preserving non-BMP characters), validates non-negative integer inputs and `0..=65535` close codes, maps `TENDRIL_WOULD_BLOCK` and `TENDRIL_EOF` into JSON status sentinels, and frees all returned C strings with `tendril_string_free`.
- `TendrilEndpoint` and `TendrilSession` in `TendrilClient.kt` implement `java.io.Closeable` with `ReentrantReadWriteLock` / `ReentrantLock` handle synchronization so concurrent `close()` calls cannot race active FFI polls or sends.
- `KeystoreStateCipher.kt` provides a standalone AES-256-GCM sealing helper (`12`-byte random IV prefix) backed by a hardware `AndroidKeyStore` key; `TendrilEndpoint` itself delegates on-disk identity and roster storage inside `stateDir` to `tendril-ffi` `StateStore`.
- `TendrilForegroundService.kt` maintains a `dataSync` foreground notification and monitors `ConnectivityManager.registerDefaultNetworkCallback` across Wi-Fi and cellular handoffs.
- `bindings/kotlin/test/TendrilJniConformanceTest.java` validates all four helper vectors (`fingerprints.json`, `pairing_mac.json`, `rotation.json`, `grants.json`) and bidirectional live interop against `tendril-conformance-peer` on host Linux JVM (`make bindings/jni` tests the C JNI bridge and Java declarations; compiling `.kt` Android sources requires Gradle and the Android SDK).

## Apple Swift (`bindings/swift`)

- `bindings/swift/Package.swift` declares `CTendril` (`module.modulemap` + `shim.h` referencing `crates/tendril-ffi/include/tendril.h`), the synchronized `Tendril` wrapper module (`TendrilCrypto`, `TendrilEndpoint`, `TendrilSession`, including `serveRelay`), `TendrilKeychainStore` (standalone Keychain + `CryptoKit` AES-GCM master-key sealing helper), and `TendrilTests` (offline vectors, fork rejection, and local endpoint lifecycle).
- Verification note: SwiftPM compilation and `XCTest` execution (`TendrilConformanceTests.swift`) require Apple macOS/iOS toolchains and were not executed on Linux.

## Gate #7 baselines

| Artifact | Target | Raw Size | Stripped / Compressed | Measurement Method |
|---|---|---|---|---|
| `bindings/web/pkg/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`) | 782,671 bytes (764.3 KiB) | 293,230 bytes (286.4 KiB) gzipped | `wasm-bindgen --target web` after release build |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26) | 3,412,800 bytes | 3,412,472 bytes (3.25 MiB) stripped | `stat -c%s` before and after `llvm-strip` |
| `aarch64-apple-ios` static archive | `aarch64-apple-ios` | Not measured on Linux | Not measured on Linux | Requires Apple Xcode toolchain |

## Gate #8 Chromium WASM Argon2id timings

Measured in headless Google Chrome via `bindings/web/test/browser_e2e.mjs` (`benchmarkArgon2`):

| Execution Context | Runs | Min (ms) | Median (ms) | Max (ms) | Notes |
|---|---|---|---|---|---|
| Browser main thread (`useWorker: false`) | 3 | 158.6 | 159.4 | 163.9 | Single-call `compute_code_mac` (`t=3, m=64 MiB, p=1`) |
| Web Worker (`useWorker: true`) | 2 | 168.7 | 193.8 | 193.8 | Includes worker spawn and WASM initialization overhead |

Physical phone Chrome/Safari Argon2id timings and manual Gate #9 Wi-Fi/cellular transition timing remain pending device testing against the live demo stack.

## Verification commands

```bash
make bindings/wasm      # Build release WASM and generate bindings/web/pkg
make bindings/web       # Run headless Chrome vector + benchmark + live relay E2E suite
make bindings/jni       # Compile libtendril_jni.so and run JVM vector + interop tests
make bindings/android   # Cross-compile release libtendril_ffi.so for aarch64-linux-android
make bindings/check     # Run Go, Python, Node, Web WASM, and Kotlin JNI suites
```

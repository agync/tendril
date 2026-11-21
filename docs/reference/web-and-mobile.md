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

`crates/tendril-wasm` compiles cleanly for `wasm32-unknown-unknown` using `.cargo/config.toml` (`getrandom_backend="wasm_js"`). Its default build (`bindings/web/pkg`) remains strictly sans-I/O and exports four stateful types plus nine helper functions; enabling the opt-in `p2p-iroh` feature (`bindings/web/pkg-p2p`) adds `WasmIrohStream` and `parse_p2p_endpoint_json` over `iroh` 1.5 (`ws_stream_wasm` + `ring`):

- `WasmIdentity`: generates, exports, and restores client hybrid Ed25519 + ML-DSA-65 signing keys (`signing_pub`, `signing_pub_hash`, `relay_pub`) and X25519 static keys without touching host storage directly, and mints single-use M2M enrollment tokens via `mint_enrollment_token`.
- `WasmRoster`: serializes and atomically replaces (`replace_from_json`) pinned hosts, pairing state, verified CRL sequence tracking, and M2M trust anchors (`add_trust_anchor`, `revoke_trust_anchor`).
- `WasmPairInitiator`: sans-I/O `Intent::Pair` handshake state machine outputting raw wire frames (`start`, `feed_bytes`), verifying `HostHello.signing_pub` against `host_signing_pub_hash_b64` / full key pins, and supporting both pairing codes and M2M enrollment tokens (`WasmPairInitiator.new_m2m`).
- `WasmSessionClient`: sans-I/O `Intent::Session` initiator supporting encrypted `send_data`, `send_ping`, `send_rekey`, `send_close`, `tick`, and `authorize`.
- Vector and verification helpers: `device_id`, `fingerprint_host`, `fingerprint_device`, `pairing_sas`, `compute_code_mac`, `compute_code_mac_bytes` (zeroizing the caller byte slice after hashing), `verify_rotation_chain_json`, `verify_grant_json`, and `parse_pairing_uri_json`.
- Opt-in browser P2P (`p2p-iroh` feature): `WasmIrohStream` (`dial`, `send_chunk`, `recv_chunk`, `close`) and `parse_p2p_endpoint_json`.

### `@tendril/web` (`bindings/web`)

- `bindings/web/src/relay.js` implements the `spec/relay-v1.md` client WebSocket handshake (`challenge`, `dial`, `ready`), URL validation (`validateRelayWsUrl`: rejecting control characters, userinfo, fragments, metadata/link-local/unspecified hosts, and cleartext `ws://` off-loopback unless `allowInsecureWs: true` is passed), binary frame bounds (`65,521` bytes max), and bounded receive queueing (`MAX_QUEUED_BYTES = 16 * 65521`, `MAX_QUEUED_FRAMES = 256`, late post-close frame drops, and queue cleanup on `close()`).
- `bindings/web/src/index.js` dynamically imports `./iroh.js` (`bindings/web/pkg-p2p/` on demand for `iroh://`), serializes cipher-state advances and multi-chunk frame flushes via `#sendChain` (`#recvChain` for `pollEvent`) while keeping `stream.recv()` unblocked, rolls back roster changes on `onPersistRoster` failure (and fails closed if revocation persistence fails), guards `TendrilWebClient.free()` by aborting active sessions and deferring WASM `free()` until in-flight holds release, and exposes `TendrilWebClient.{addTrustAnchor, revokeTrustAnchor, mintEnrollmentToken, enroll}` for browser M2M workflows.
- `bindings/web/src/worker.js` and `computeCodeMacWorker` (`code: string | Uint8Array`, `handshakeHash`, `{ timeoutMs }`) move Argon2id pairing-code proof computation off the UI thread, transferring and zeroing `Uint8Array` secret code inputs and terminating hung or unserializable workers on timeout or `messageerror`; `computeCodeMacBytes` exposes the synchronous zeroizing path directly.
- `bindings/web/demo/` provides an interactive pairing/session web page supporting both `wss://.../v1/relay` and `iroh://...` endpoints, serving strict `Content-Security-Policy` (`frame-ancestors 'none'`, `'wasm-unsafe-eval'`), `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer` headers, allowlisting static `/demo/` assets (`404` on `/demo/server.mjs`), enforcing RFC 6455 WebSocket upgrade header/timeout validation in `server.mjs`, enforcing `/demo-config.json` precedence + URL secret scrubbing + third-party override warnings in `app.js`, and sealing identity/roster JSON in IndexedDB (`tendril-demo-vault-v1`) under a non-extractable WebCrypto AES-256-GCM key rather than plaintext `localStorage`.
- `bindings/web/test/security.test.mjs` and `bindings/web/test/browser_e2e.mjs` verify URL/queue/concurrency/persistence/lifecycle hardening, zeroizing worker MAC helpers, M2M enrollment/replay/anchor-revocation flows over live WSS relay, `spec/vectors/`, `parseP2pEndpoint` validation, and live headless Chrome `Noise_XXhfs` relay flows against `tendril-relay` and `tendril-conformance-peer` (plus live `iroh://` browser-to-host E2E over n0 public relays when `TENDRIL_WEB_P2P_LIVE=1`).

## Android Kotlin JNI (`bindings/kotlin`)

- `bindings/kotlin/jni/tendril_jni.c` bridges `dev.tendril.TendrilNative` methods (including `endpointAddTrustAnchor`, `endpointRevokeTrustAnchor`, `endpointMintEnrollmentToken`, and `endpointEnrollInitiate`) to `crates/tendril-ffi/include/tendril.h`, converts standard UTF-8 <-> UTF-16 directly (preserving non-BMP characters and formatting dynamic full-length FFI error messages), rejects embedded NUL bytes in string inputs, validates non-negative integer inputs and `0..=65535` close codes, maps `TENDRIL_WOULD_BLOCK` and `TENDRIL_EOF` into JSON status sentinels, and frees all returned C strings with `tendril_string_free`.
- `TendrilEndpoint` and `TendrilSession` in `TendrilClient.kt` expose full M2M enrollment (`addTrustAnchor`, `revokeTrustAnchor`, `mintEnrollmentToken`, `enrollInitiate`) and implement `java.io.Closeable` with `ReentrantReadWriteLock` handle synchronization, calling `tendril_endpoint_close` / `tendril_session_shutdown` outside exclusive native free so concurrent `close()` calls unblock and serialize safely against active FFI polls or sends.
- `KeystoreStateCipher.kt` (`SealedStateStore`) seals and unseals identity and roster JSON via an `AndroidKeyStore` AES-256-GCM key (`12`-byte random IV prefix, version `0x01`, domain AAD, verifying Keystore key presence), wired directly into `TendrilEndpoint.create` / `TendrilSession` via `tendril_endpoint_new_from_state` while `AndroidManifest.xml` disables cloud/ADB backups (`android:allowBackup="false"`, `tendril_backup_rules.xml`, `tendril_data_extraction_rules.xml`).
- `TendrilForegroundService.kt` maintains a `dataSync` foreground notification and monitors `ConnectivityManager.registerDefaultNetworkCallback` across Wi-Fi and cellular handoffs.
- `bindings/kotlin/test/TendrilJniConformanceTest.java` validates all four helper vectors (`fingerprints.json`, `pairing_mac.json`, `rotation.json`, `grants.json`), NUL/close hardening, bidirectional live interop against `tendril-conformance-peer`, and M2M enrollment/replay/anchor-revocation on host Linux JVM (`make bindings/jni` tests the C JNI bridge and Java declarations; compiling `.kt` Android sources requires Gradle and the Android SDK).

## Apple Swift (`bindings/swift`)

- `bindings/swift/Package.swift` declares `CTendril` (`module.modulemap` + `shim.h` referencing `crates/tendril-ffi/include/tendril.h`), the `Tendril` wrapper module (`TendrilCrypto`, `TendrilEndpoint` including `addTrustAnchor`, `revokeTrustAnchor`, `mintEnrollmentToken`, and `enrollInitiate`, plus `TendrilSession`, validating strings against embedded NUL bytes and using `NSCondition` active-call refcounting with `tendril_endpoint_close`/`tendril_session_shutdown`), `TendrilKeychainStore` (`SealedSwiftStateStore` handling `errSecDuplicateItem`, key buffer zeroization, version `0x01` + domain AAD `CryptoKit` AES-GCM sealing wired into `TendrilEndpoint`/`TendrilSession`), and `TendrilTests` (offline vectors, fork rejection, local endpoint lifecycle, and M2M enrollment/replay checks).
- Verification note: SwiftPM compilation and `XCTest` execution (`TendrilConformanceTests.swift`) require Apple macOS/iOS toolchains and were not executed on Linux.

## Gate #7 baselines

| Artifact | Target | Raw Size | Stripped / Compressed | Measurement Method |
|---|---|---|---|---|
| `bindings/web/pkg/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`, default sans-I/O, hybrid PQ) | 1,027,782 bytes (1003.7 KiB) | 363,833 bytes (355.3 KiB) gzipped | Wave 2 `wasm-bindgen --target web` + `gzip -c -9` |
| `bindings/web/pkg-p2p/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`, `--features p2p-iroh`, hybrid PQ) | 4,279,199 bytes (4.08 MiB) | 1,565,104 bytes (1.49 MiB) gzipped | Wave 2 `wasm-bindgen --target web` (`p2p-iroh`) + `gzip -c -9` |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26, `--no-default-features`) | 3,434,576 bytes | 3,434,248 bytes (3.28 MiB, pre-PQ baseline) | `stat -c%s` before and after `llvm-strip` |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26, default `p2p-iroh`) | 12,291,992 bytes | 12,291,664 bytes (11.72 MiB, pre-PQ baseline) | `stat -c%s` before and after `llvm-strip` |
| `aarch64-apple-ios` static archive | `aarch64-apple-ios` | Not measured on Linux | Not measured on Linux | Requires Apple Xcode toolchain |

## Gate #8 WASM Argon2id timings

Measured via `benchmarkArgon2` (`t=3, m=64 MiB, p=1`) in headless desktop Google Chrome (`bindings/web/test/browser_e2e.mjs`) and on a physical mobile phone browser over TLS relay demo:

| Execution Context | Runs | Min (ms) | Median (ms) | Max (ms) | Notes |
|---|---|---|---|---|---|
| Desktop headless Chrome (main thread) | 3 | 158.6 | 159.4 | 163.9 | Single-call `compute_code_mac` (`useWorker: false`) |
| Desktop headless Chrome (Web Worker) | 2 | 168.7 | 193.8 | 193.8 | Includes worker spawn and WASM init (`useWorker: true`) |
| Mobile phone browser (main thread) | 3 | 153.8 | 155.8 | 171.7 | Physical phone run against hosted demo (`useWorker: false`) |
| Mobile phone browser (Web Worker) | 3 | 402.6 | 665.7 | 1030.9 | Includes worker spawn and WASM init per call (`useWorker: true`) |

## Gate #9 real-device pairing and reconnect baselines

### WebSocket relay baseline (physical phone)

Observed between a physical mobile browser and the desktop Rust `tendril` CLI host over the WebSocket relay demo (`< 30 s` pairing target):

- **Remote pairing:** `0.59 s` end-to-end with verified 16-character SAS match and host `tendril confirm`.
- **Authenticated session connect:** `332.1 ms` initial Noise XX handshake over relay (`164.5 ms` repeat connect).
- **Encrypted control and data round-trip:** `27 ms` encrypted `0x05 PING` -> `0x06 PONG`, followed by `0x04 REKEY` and verified plaintext delivery (`21` bytes) decoded on the Rust host.
- **Disconnect and reconnect recovery:** Re-established authenticated relay sessions in `526.5 ms`, `520.4 ms`, and `418.0 ms` across manual reconnect and connectivity restoration tests.

### Zero-setup `iroh://` baseline (physical phone, Tailscale OFF)

Observed between a physical mobile browser (Tailscale OFF, zero self-hosted Tendril relay) and `tendril serve --p2p --issue-code remote` over bare `iroh://` routed via public `n0` relay (`euc1-1.relay.n0.iroh.link.`):

- **Warm remote pairing:** `0.87 s` with verified 16-character SAS match and host `tendril confirm` (a cold first tap timed out while downloading the uncompressed `3.93 MiB` `pkg-p2p` bundle inside the shared `15 s` timeout, motivating `initTendrilP2p()` pre-warming and gzip compression in `demo/server.mjs`).
- **Authenticated session connect (`provider: P2p`):** `634.9 ms` initial Noise XX QUIC establish.
- **Encrypted control and data round-trip:** `63 ms`, `67 ms`, and post-rekey `69 ms` `0x05 PING` -> `0x06 PONG` RTTs, followed by `0x04 REKEY` and `21`-byte plaintext verified on the Rust host.
- **Disconnect and reconnect recovery:** Clean session close (`code=1000`, `reason="reconnect"`) and re-establishment in `392.9 ms` over `provider: P2p`.

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

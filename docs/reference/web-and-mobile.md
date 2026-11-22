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

- `WasmIdentity`: generates, exports, and restores client hybrid Ed25519 + ML-DSA-65 signing keys (`signing_pub`, `signing_pub_hash`, `relay_pub`) and X25519 static keys without touching host storage directly, mints single-use M2M enrollment tokens via `mint_enrollment_token`, and mints Tier 3 relay tickets via `mint_relay_ticket_json`.
- `WasmRoster`: serializes and atomically replaces (`replace_from_json`) pinned hosts, pairing state, verified CRL sequence tracking, M2M trust anchors (`add_trust_anchor`, `revoke_trust_anchor`), and v2 peer metadata (`pairing_floor`, `peer_v2_summary`, `derive_v2_relay_dial_for_peer_json`).
- `WasmPairInitiator` and `WasmV2PakePairInitiator`: sans-I/O `Intent::Pair` handshake state machines (`start`, `feed_bytes`). `WasmPairInitiator` drives v1 pairing and M2M enrollment (`WasmPairInitiator.new_m2m`), with `new_with_roster` and `new_m2m_with_roster` enforcing persisted `min_wire_version` upgrade floors; `WasmV2PakePairInitiator` drives Wire `0x02` PAKE pairing.
- `WasmSessionClient` and `WasmV2SessionInitiator`: sans-I/O `Intent::Session` initiators (v1 `WasmSessionClient`: `send_data`, `send_ping`, `send_rekey`, `send_close`, `tick`, `authorize`; v2 `WasmV2SessionInitiator`: `send_data`, `rekey`, `close`, `tick`, `authorize`, `send_dummy_cover`, `next_ping_delay_ms`, `send_ping` for Wire `0x02` pseudonymous reconnect with padded/jittered frames).
- Vector and verification helpers: `device_id`, `fingerprint_host`, `fingerprint_device`, `pairing_sas`, `compute_code_mac`, `compute_code_mac_bytes` (zeroizing the caller byte slice after hashing), `verify_rotation_chain_json`, `verify_grant_json`, `parse_pairing_uri_json`, `compute_relay_auth_hmac_b64`, `canonical_relay_host` (normalizing IPv6, trailing-dot, and mixed-case hosts while preserving raw v1 HMAC hosts), `derive_v2_relay_dial_json`, and `v2_epoch_within_skew`.
- Opt-in browser P2P (`p2p-iroh` feature): `WasmIrohStream` (`dial`, `dial_with_options`, `send_chunk`, `recv_chunk`, `close`) and `parse_p2p_endpoint_json`.

### `@tendril-sdk/web` (`bindings/web`)

- `bindings/web/src/relay.js` implements `spec/relay-v1.md` (`/v1/relay`) and `spec/relay-v2.md` (`/v2/relay` via `dialRelayV2Stream`, requiring `deriveV2Dial` for epoch-blinded `dial_token` proofs) client WebSocket handshakes (`challenge`, `dial`, `ready`, plus Tier 2 HMAC `computeRelayAuthHmacB64` and Tier 3 `RelayTicket` admission proofs), canonical relay host normalization (`canonicalRelayHost` / `canonical_relay_host`), URL validation (`validateRelayWsUrl`: rejecting control characters, userinfo, fragments, metadata/link-local/unspecified hosts, and cleartext `ws://` off-loopback unless `allowInsecureWs: true` is passed), binary frame bounds (`65,521` bytes max), and bounded receive queueing (`MAX_QUEUED_BYTES = 16 * 65521`, `MAX_QUEUED_FRAMES = 256`, late post-close frame drops, and queue cleanup on `close()`).
- `bindings/web/src/index.js` dynamically imports `./iroh.js` (`bindings/web/pkg-p2p/` on demand for `iroh://`, isolating `?relay=` URI hints onto custom relays with `n0` DNS/Pkarr off and bearer token guard `p2pRelayAuthToken`, supporting `p2pRelayUrls` for managed `iroh-relay` pools, and rejecting `p2pApiSecret` in the browser so API secrets are never embedded in client JS), serializes cipher-state advances and multi-chunk frame flushes via `#sendChain` (`#recvChain` for `pollEvent`) while keeping `stream.recv()` unblocked, prefers `onPersistRosterBytes` over string `onPersistRoster` when both are provided (zeroizing the `Uint8Array` after `await`) and rolls back roster changes on persistence failure (failing closed if revocation persistence fails), guards `TendrilWebClient.free()` by aborting active sessions and deferring WASM `free()` until in-flight holds release, zeroizes `Uint8Array` secret inputs in `finally` blocks, exports top-level `@tendril-sdk/web` helpers (`canonicalRelayHost`, `computeRelayAuthHmacB64`, `deriveV2RelayDial`, `v2EpochWithinSkew`, `createIndexedDbVault`, `openTendrilVault`), and exposes `TendrilWebClient.{pairV2, connectV2, mintRelayTicket, addTrustAnchor, revokeTrustAnchor, mintEnrollmentToken, enroll}` and `TendrilWebSession.ping(cookie?)` (wrapping `WasmV2SessionInitiator::send_ping`) for Wire `0x02` and browser M2M workflows.
- `bindings/web/src/vault.js` exports `createIndexedDbVault` (aliased as `openTendrilVault`), a reusable WebCrypto AES-256-GCM IndexedDB vault for sealing identity and roster bytes/strings under a non-extractable AES-256-GCM key.
- `bindings/web/src/worker.js` and `computeCodeMacWorker` (`code: string | Uint8Array`, `handshakeHash`, `{ timeoutMs }`) move Argon2id pairing-code proof computation off the UI thread, transferring and zeroing `Uint8Array` secret code inputs and terminating hung or unserializable workers on timeout or `messageerror`; `computeCodeMacBytes` exposes the synchronous zeroizing path directly.
- `bindings/web/demo/` provides an interactive pairing/session web page supporting `wss://.../v1/relay`, `wss://.../v2/relay` proxy routing, and `iroh://...` endpoints, serving strict `Content-Security-Policy` (`frame-ancestors 'none'`, `'wasm-unsafe-eval'`), `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer` headers, allowlisting static `/demo/` assets (`404` on `/demo/server.mjs`), enforcing RFC 6455 WebSocket upgrade header/timeout validation in `server.mjs`, enforcing `/demo-config.json` precedence + fragment-only `#code=` / `#uri=` secrets (ignoring and scrubbing query-string secrets with a warning) + a log redaction toggle (default ON) + third-party override warnings in `app.js`, and sealing identity/roster bytes in IndexedDB (`tendril-demo-vault-v1`) via `createIndexedDbVault`.
- `bindings/web/test/security.test.mjs` and `bindings/web/test/browser_e2e.mjs` verify URL/queue/concurrency/persistence/lifecycle hardening, zeroizing worker MAC helpers, M2M enrollment/replay/anchor-revocation flows over live WSS relay, `spec/vectors/`, `parseP2pEndpoint` validation, and live headless Chrome `Noise_XXhfs` relay flows against `tendril-relay` and `tendril-conformance-peer` (plus live `iroh://` browser-to-host E2E over n0 public relays when `TENDRIL_WEB_P2P_LIVE=1`).

## Android Kotlin JNI (`bindings/kotlin`)

- `bindings/kotlin/jni/tendril_jni.c` bridges `dev.tendril.TendrilNative` methods (including `endpointAddTrustAnchor`, `endpointRevokeTrustAnchor`, `endpointMintEnrollmentToken`, and `endpointEnrollInitiate`) to `crates/tendril-ffi/include/tendril.h`, converts standard UTF-8 <-> UTF-16 directly (preserving non-BMP characters and formatting dynamic full-length FFI error messages), rejects embedded NUL bytes in string inputs, validates non-negative integer inputs and `0..=65535` close codes, maps `TENDRIL_WOULD_BLOCK` and `TENDRIL_EOF` into JSON status sentinels, and frees all returned C strings with `tendril_string_free`.
- `TendrilEndpoint` and `TendrilSession` in `TendrilClient.kt` expose full M2M enrollment (`addTrustAnchor`, `revokeTrustAnchor`, `mintEnrollmentToken`, `enrollInitiate`) and implement `java.io.Closeable` with `ReentrantReadWriteLock` handle synchronization, calling `tendril_endpoint_close` / `tendril_session_shutdown` outside exclusive native free so concurrent `close()` calls unblock and serialize safely against active FFI polls or sends.
- `KeystoreStateCipher.kt` (`SealedStateStore`) seals and unseals identity and roster JSON via an `AndroidKeyStore` AES-256-GCM key (`12`-byte random IV prefix, version `0x01`, domain AAD, verifying Keystore key presence), wired directly into `TendrilEndpoint.create` / `TendrilSession` via `tendril_endpoint_new_from_state` while `AndroidManifest.xml` disables cloud/ADB backups (`android:allowBackup="false"`, `tendril_backup_rules.xml`, `tendril_data_extraction_rules.xml`).
- `TendrilForegroundService.kt` maintains a `dataSync` foreground notification and monitors `ConnectivityManager.registerDefaultNetworkCallback` across Wi-Fi and cellular handoffs.
- `bindings/kotlin/test/TendrilJniConformanceTest.java` validates all four helper vectors (`fingerprints.json`, `pairing_mac.json`, `rotation.json`, `grants.json`), NUL/close hardening, bidirectional live interop against `tendril-conformance-peer`, and M2M enrollment/replay/anchor-revocation on host Linux JVM (`make bindings/jni` tests the C JNI bridge and Java declarations; compiling `.kt` Android sources requires Gradle and the Android SDK).
- `crates/tendril-ffi/build.rs` sets `DT_SONAME=libtendril_ffi.so` and `-Wl,-z,max-page-size=16384` (16 KB ELF page alignment, matched in `bindings/kotlin/jni/CMakeLists.txt`), and `TendrilAndroidSmokeTest` (3/3 instrumentation tests: `KeystoreStateCipher` AES-GCM AAD binding, `TendrilEndpoint` sealed identity persistence plus M2M enrollment token minting, and `configureTransportsJson` plus `RelayTicket` minting) passed on a physical `arm64-v8a` Android 15 device via `bindings/kotlin/scripts/adb-smoke.sh`.

## Apple Swift (`bindings/swift`)

- `bindings/swift/Package.swift` declares `CTendril` (`module.modulemap` + `shim.h` referencing `crates/tendril-ffi/include/tendril.h`), the `Tendril` wrapper module (`TendrilCrypto`, `TendrilEndpoint` including `addTrustAnchor`, `revokeTrustAnchor`, `mintEnrollmentToken`, and `enrollInitiate`, plus `TendrilSession`, validating strings against embedded NUL bytes and using `NSCondition` active-call refcounting with `tendril_endpoint_close`/`tendril_session_shutdown`), `TendrilKeychainStore` (`SealedSwiftStateStore` handling `errSecDuplicateItem`, key buffer zeroization, version `0x01` + domain AAD `CryptoKit` AES-GCM sealing wired into `TendrilEndpoint`/`TendrilSession`), and `TendrilTests` (offline vectors, fork rejection, local endpoint lifecycle, and M2M enrollment/replay checks).
- Verification note: `swift test` (`TendrilConformanceTests`, 7/7 tests) and `aarch64-apple-darwin` (macOS arm64) release builds pass on macOS arm64; with full `Xcode.app` (`iPhoneOS` and `iPhoneSimulator` SDKs), `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `TendrilFFI.xcframework` (3 `arm64` slices), and `xcodebuild -scheme Tendril` builds for `generic/platform=iOS` and `generic/platform=iOS Simulator` all pass.

## Gate #7 baselines

| Artifact | Target | Raw Size | Stripped / Compressed | Measurement Method |
|---|---|---|---|---|
| `bindings/web/pkg/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`, default sans-I/O, hybrid PQ) | 1,027,782 bytes (1003.7 KiB) | 363,831 bytes (355.3 KiB) gzipped | `wasm-bindgen --target web` + `gzip -c -9` |
| `bindings/web/pkg-p2p/tendril_wasm_bg.wasm` | `wasm32-unknown-unknown` (`release`, `--features p2p-iroh`, hybrid PQ) | 4,279,199 bytes (4.08 MiB) | 1,565,110 bytes (1.49 MiB) gzipped | `wasm-bindgen --target web` (`p2p-iroh`) + `gzip -c -9` |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26, `--no-default-features`, hybrid PQ) | 4,095,168 bytes (3.91 MiB) | 4,095,160 bytes (3.91 MiB) | `stat -c%s` before and after `llvm-strip` |
| `target/aarch64-linux-android/release/libtendril_ffi.so` | `aarch64-linux-android` (`release`, API 26, default `p2p-iroh`, hybrid PQ) | 12,761,016 bytes (12.17 MiB) | 12,761,008 bytes (12.17 MiB) | `stat -c%s` before and after `llvm-strip` |
| Android Gradle release AAR (`bindings/kotlin`) | `aarch64-linux-android` (`release`, hybrid PQ) | 5,800,485 bytes (5.53 MiB) | Packaged AAR | Gradle `assembleRelease` |
| `target/release/libtendril_ffi.{dylib,a}` | `aarch64-apple-darwin` (`release`, `--no-default-features`, hybrid PQ) | 3,984,240 B `.dylib` / 56,631,288 B `.a` | 3,984,304 B (`strip -x`) / 12,489,976 B (`strip -S`) | macOS arm64 release build + `strip` |
| `target/release/libtendril_ffi.{dylib,a}` | `aarch64-apple-darwin` (`release`, default `p2p-iroh`, hybrid PQ) | 11,255,888 B `.dylib` / 124,318,248 B `.a` | 11,255,976 B (`strip -x`) / 29,375,784 B (`strip -S`) | macOS arm64 release build + `strip` |
| `target/aarch64-apple-ios/release/libtendril_ffi.a` | `aarch64-apple-ios` (`release`, `--no-default-features`, hybrid PQ) | 60,811,456 bytes (58.0 MiB) | 13,822,496 bytes (13.2 MiB) (`strip -S`) | macOS arm64 cross-compile with Xcode `iphoneos` SDK + `strip -S` |
| `target/aarch64-apple-ios/release/libtendril_ffi.a` | `aarch64-apple-ios` (`release`, default `p2p-iroh`, hybrid PQ) | 124,352,056 bytes (118.6 MiB) | 30,231,680 bytes (28.8 MiB) (`strip -S`) | macOS arm64 cross-compile with Xcode `iphoneos` SDK + `strip -S` |
| `target/aarch64-apple-ios-sim/release/libtendril_ffi.a` | `aarch64-apple-ios-sim` (`release`, default `p2p-iroh`, hybrid PQ) | 124,295,080 bytes (118.5 MiB) | 30,141,360 bytes (28.7 MiB) (`strip -S`) | macOS arm64 cross-compile with Xcode `iphonesimulator` SDK + `strip -S` |
| `TendrilFFI.xcframework` zip (`macos-arm64`, `ios-arm64`, `ios-arm64-simulator`) | Apple XCFramework (`release`, default `p2p-iroh`, hybrid PQ) | 126,699,994 bytes (120.8 MiB) | Packaged zip | `xcodebuild -create-xcframework` + `ditto -c -k` |

## Gate #8 WASM Argon2id timings

Measured via `benchmarkArgon2` (`t=3, m=64 MiB, p=1`) in headless desktop Google Chrome (`bindings/web/test/browser_e2e.mjs`) and on a physical mobile phone browser over TLS relay demo:

| Execution Context | Runs | Min (ms) | Median (ms) | Max (ms) | Notes |
|---|---|---|---|---|---|
| Desktop headless Chrome (main thread) | 3 | 135.2 | 148.5 | 158.7 | Single-call `compute_code_mac` (`useWorker: false`, post-`ADR 0004`) |
| Desktop headless Chrome (Web Worker) | 2 | 183.7 | 218.7 | 218.7 | Includes worker spawn and WASM init (`useWorker: true`, post-`ADR 0004`) |
| Mobile phone browser (main thread) | 3 | 153.8 | 155.8 | 171.7 | Physical phone run against hosted demo (`useWorker: false`) |
| Mobile phone browser (Web Worker) | 3 | 402.6 | 665.7 | 1030.9 | Includes worker spawn and WASM init per call (`useWorker: true`) |

## Gate #9 pairing and reconnect baselines

### Desktop headless Chrome WebSocket relay (post-`ADR 0004` `Noise_XXhfs`)

Measured in headless desktop Google Chrome against `tendril-conformance-peer` over a loopback `tendril-relay` (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, `1216 B` `msg1`, and `3373 B` hybrid `Ed25519 + ML-DSA-65` signatures):

- **Remote pairing (`TendrilWebClient.pair`):** `269.4 ms` end-to-end (includes `Noise_XXhfs` `pair` handshake and Argon2id `code_mac`).
- **Authenticated session connect (`TendrilWebClient.connect`):** `18.0 ms` initial `Noise_XXhfs` handshake over loopback relay (`14.6 ms` repeat connect).
- **Encrypted control and data round-trip:** `25.5 ms` encrypted `0x05 PING` -> `0x06 PONG` RTT, `0.2 ms` client `0x04 REKEY` dispatch, and verified `21`-byte plaintext delivery on the Rust conformance peer.

These desktop headless figures are local loopback baselines and are not directly comparable to WAN physical-phone latencies.

### Historical pre-`ADR 0004` physical-phone baselines

> [!NOTE]
> The two physical-phone subsections below are **historical pre-`ADR 0004` baselines** measured under classical `Noise_XX` before `1216 B` `Noise_XXhfs` `msg1` and `3373 B` hybrid `Ed25519 + ML-DSA-65` signatures landed in wire v1. Physical-phone re-measurement under `Noise_XXhfs` is pending.

#### WebSocket relay baseline (physical phone, pre-`ADR 0004` classical `Noise_XX`)

Observed between a physical mobile browser and the desktop Rust `tendril` CLI host over the WebSocket relay demo (`< 30 s` pairing target):

- **Remote pairing:** `0.59 s` end-to-end with verified 16-character SAS match and host `tendril confirm`.
- **Authenticated session connect:** `332.1 ms` initial pre-`ADR 0004` classical `Noise_XX` handshake over relay (`164.5 ms` repeat connect).
- **Encrypted control and data round-trip:** `27 ms` encrypted `0x05 PING` -> `0x06 PONG`, followed by `0x04 REKEY` and verified plaintext delivery (`21` bytes) decoded on the Rust host.
- **Disconnect and reconnect recovery:** Re-established authenticated relay sessions in `526.5 ms`, `520.4 ms`, and `418.0 ms` across manual reconnect and connectivity restoration tests.

#### Zero-setup `iroh://` baseline (physical phone, Tailscale OFF, pre-`ADR 0004` classical `Noise_XX`)

Observed between a physical mobile browser (Tailscale OFF, zero self-hosted Tendril relay) and `tendril serve --p2p --issue-code remote` over bare `iroh://` routed via public `n0` relay (`euc1-1.relay.n0.iroh.link.`):

- **Warm remote pairing:** `0.87 s` with verified 16-character SAS match and host `tendril confirm` (a cold first tap timed out while downloading the uncompressed `3.93 MiB` `pkg-p2p` bundle inside the shared `15 s` timeout, motivating `initTendrilP2p()` pre-warming and gzip compression in `demo/server.mjs`).
- **Authenticated session connect (`provider: P2p`):** `634.9 ms` initial pre-`ADR 0004` classical `Noise_XX` QUIC establish.
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

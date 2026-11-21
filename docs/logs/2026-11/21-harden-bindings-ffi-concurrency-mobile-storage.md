---
type: Log Entry
title: "Harden bindings, FFI concurrency, mobile storage, and web SDK (Audit Batch 2B)"
description: "Harden bindings, FFI concurrency, mobile storage, and web SDK (Audit Batch 2B)"
tags: [log, update]
kind: Update
status: stable
---

Harden runtime session concurrency, FFI and language bindings, mobile keystore storage, browser Web SDK, and demo server (Audit Batch 2B).

- Runtime and C ABI (`tendril-runtime`, `crates/tendril-ffi`): split transport streams (`PathStream::into_split`) behind `ConcurrentSession` (`reader -> writer -> machine -> roster -> pending_events`, `shutdown()`, fresh `current_unix_secs` checks), zeroize returned strings in `tendril_string_free`, truncate `tendril_last_error` at UTF-8 char boundaries, guard `tendril_session_send_data` against `len > MAX_APP_DATA_LEN`, and add `tendril_endpoint_new_from_state`, `tendril_endpoint_close`, `tendril_session_shutdown`, and state export symbols.
- Go, Python, Node, Kotlin/Android, and Swift bindings: validate safe integers in Node, reject embedded NUL bytes across Go/JNI/Swift strings, upgrade `Endpoint`/`Session` locks to support concurrent full-duplex operations and clean `close()` wakeups, disable Android cloud/ADB backups (`android:allowBackup="false"`), wire `SealedStateStore` (`AndroidKeyStore`) and `SealedSwiftStateStore` (Keychain + `CryptoKit`) into mobile `TendrilEndpoint`/`TendrilSession` lifecycles, and harden JNI UTF-16 error conversion.
- Web SDK and demo (`crates/tendril-wasm`, `bindings/web`): enforce relay WebSocket URL checks (`allowInsecureWs` opt-in off loopback, SSRF/userinfo/fragment/control-char guards), cap `RelayStream` receive buffers, serialize `TendrilWebSession` frame writes via `#sendChain`/`#recvChain`, roll back or fail closed on `onPersistRoster` errors (`WasmRoster::replace_from_json`), prevent `TendrilWebClient.free()` WASM null-pointer traps, harden `demo/server.mjs` headers/allowlists/upgrades, scrub URL secrets in `demo/app.js`, and move demo keys into a non-extractable WebCrypto AES-256-GCM IndexedDB vault. Updated [FFI ABI and cross-language bindings](../../reference/ffi-and-bindings.md) and [Web and mobile bindings](../../reference/web-and-mobile.md).

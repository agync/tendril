---
type: Reference
title: FFI ABI and cross-language bindings
description: Callback-free C ABI surface, thin Go/Python/Node bindings, and Gate #7 binary size and FFI latency baselines.
status: stable
tags: [reference, ffi, bindings]
---

# FFI ABI and cross-language bindings

Tendril keeps one Rust core (`tendril-core` + `tendril-runtime`) across every target language. Host-language bindings delegate wire framing, Noise handshakes, pairing codes, roster persistence, rotation verification, and default-deny capability checks directly to Rust rather than duplicating protocol logic.

## Core architecture

```
Host app (Go / Python / Node.js)
  -> Thin language wrapper (mutex / GIL release / N-API Promise)
    -> C ABI (`tendril-ffi`) or direct Rust bridge (PyO3 / napi-rs)
      -> `tendril-runtime` (`InboundRouter`, `StateStore`, `SessionDriver`) + `tendril-core`
```

- **Shared inbound routing (`InboundRouter`):** Peeks each incoming stream's cleartext preamble under the pre-auth rate limiter and dispatches `Intent::Pair` and `Intent::Session` streams onto separate queues (`pair_rx` and `session_rx`) so `pair_accept` and `accept_session` never block or starve each other, while `close()` wakes waiting callers immediately.
- **Durable roster persistence:** Host key rotations and rotation-fork revocations during `connect`, as well as CRL updates (including session-terminating `0x03 REVOCATION` frames), are persisted to `StateStore` across `tendril-ffi`, Python, and Node.
- **Go (`bindings/go`):** Links `libtendril_ffi` through cgo against `crates/tendril-ffi/include/tendril.h`.
- **Python (`bindings/python`):** Builds a PyO3 `abi3-py39` extension module (`tendril._tendril`) with `unsafe_code = "forbid"`, releasing the GIL via `py.detach` around Argon2 derivation (`compute_code_mac`) and every `Endpoint`/`Session` mutex, disk I/O, or blocking runtime operation (`info_json` is a lock-free metadata serialization).
- **Node.js (`bindings/node`):** Builds a `napi-rs` N-API v8 native addon (`index.node`) with `unsafe_code = "forbid"`, offloading Argon2 (`computeCodeMac`) and async session/endpoint operations onto Tokio so the JS event loop stays responsive.

## C ABI surface (`crates/tendril-ffi`)

`crates/tendril-ffi/include/tendril.h` is manually maintained in lockstep with `crates/tendril-ffi/src/lib.rs` and defines a callback-free polled C ABI backed by a multi-threaded Tokio runtime:

| Symbol Group | Representative Functions | Ownership & Error Contract |
|---|---|---|
| Status & cleanup | `tendril_last_error`, `tendril_string_free` | Negative `TendrilResult` populates thread-local error buffer; heap strings returned via `char **` must be released with `tendril_string_free` |
| Vector & core helpers | `tendril_device_id`, `tendril_fingerprint_host`, `tendril_fingerprint_device`, `tendril_pairing_sas`, `tendril_compute_code_mac`, `tendril_verify_rotation_chain_json`, `tendril_verify_grant_json` | Pure delegation to `tendril-core` with early out-pointer validation and `catch_unwind` panic boundaries |
| Endpoint lifecycle | `tendril_endpoint_new`, `tendril_endpoint_free`, `tendril_endpoint_info_json`, `tendril_endpoint_serve_direct`, `tendril_endpoint_serve_relay`, `tendril_endpoint_serve_p2p`, `tendril_endpoint_issue_code`, `tendril_endpoint_pair_initiate`, `tendril_endpoint_pair_accept`, `tendril_endpoint_confirm_peer`, `tendril_endpoint_mint_grant`, `tendril_endpoint_revoke_peer` | Opaque `TendrilEndpoint *`; NULL or empty `state_dir` selects ephemeral in-memory operation; manual `tendril_endpoint_pair_initiate` records hosts in `pending` state requiring `tendril_endpoint_confirm_peer` before `connect`; `tendril_endpoint_serve_p2p` binds a deterministic HKDF-derived `iroh` listener (`"default"`, `"disabled"`/`"local"`, or relay URL) when compiled with `p2p-iroh` |
| Session lifecycle & polling | `tendril_session_connect`, `tendril_session_accept`, `tendril_session_free`, `tendril_session_send_data`, `tendril_session_poll_event`, `tendril_session_authorize`, `tendril_session_rekey`, `tendril_session_close` | Opaque `TendrilSession *` remains valid after `tendril_endpoint_free`; `tendril_session_poll_event` validates `out_event_json` before polling and returns `TENDRIL_OK` (`0`), `TENDRIL_WOULD_BLOCK` (`1`), or `TENDRIL_EOF` (`2`) |

### `TendrilResult` status codes

- `TENDRIL_OK` (`0`): operation succeeded.
- `TENDRIL_WOULD_BLOCK` (`1`): timed poll completed with no queued event ready.
- `TENDRIL_EOF` (`2`): peer stream ended cleanly.
- Negative codes (`TENDRIL_ERR_INVALID_ARG` `-1`, `TENDRIL_ERR_NOT_FOUND` `-2`, `TENDRIL_ERR_CLOSED` `-5`, `TENDRIL_ERR_PROTOCOL` `-6`, `TENDRIL_ERR_INTERNAL` `-7`): error details are readable via `tendril_last_error`.

## Language bindings summary

### Go (`bindings/go`)

- Exposes typed wrappers (`Endpoint`, `Session`, `EndpointInfo`, `PairInitiateResult`, `PairAcceptResult`, `SessionEvent` including `Audit`, `ErrWouldBlock`), `ServeDirect`, `ServeRelay`, `ServeP2p`, and pure helper functions (`DeviceID`, `FingerprintHost`, `FingerprintDevice`, `PairingSAS`, `ComputeCodeMAC`, `VerifyRotationChainJSON`, `VerifyGrantJSON`).
- Guards `Endpoint` with `sync.RWMutex` and `Session` with `sync.Mutex`, pairs pointer and byte-slice reads with `runtime.KeepAlive`, and pins OS threads via `runtime.LockOSThread()` / `runtime.UnlockOSThread()` around cgo calls and `tendril_last_error()` reads so goroutine migration cannot lose or cross-contaminate thread-local errors under `go test -race`.

### Python (`bindings/python`)

- Exposes `Endpoint` (including `serve_direct`, `serve_relay`, `serve_p2p`, plus `pair_initiate` and `connect` delegating dialing internally to `tendril-runtime::dial_endpoint` for `iroh://`, `overlay://`, `broker+ws(s)://`, `ws(s)://`, local, and direct targets), `Session`, `device_id`, `fingerprint_host`, `fingerprint_device`, `pairing_sas`, `compute_code_mac`, `verify_rotation_chain_json`, and `verify_grant_json` from `tendril`.
- `compute_code_mac` and all blocking, mutex-acquiring, or disk-persisting `Endpoint` and `Session` methods release the GIL via `py.detach`, verified by a multi-threaded heartbeat test during concurrent `compute_code_mac` Argon2 execution and concurrent handshake threads.

### Node.js (`bindings/node`)

- Exposes `Endpoint`, `Session` (non-constructible directly via `private constructor()` in `bindings/node/index.d.ts`), synchronous hash/verifier helpers (`deviceId`, `fingerprintHost`, `fingerprintDevice`, `pairingSas`, `verifyRotationChainJson`, `verifyGrantJson`), and async `Promise` methods (`computeCodeMac`, `serveDirect`, `serveRelay`, `serveP2p`, `pairInitiate`, `pairAccept`, `connect`, `acceptSession`, `sendData`, `pollEvent`, `authorize`, `rekey`, `close`).
- Verified by a `setInterval` timer responsiveness test running alongside concurrent `computeCodeMac` Argon2 promises and local P2P (`serveP2p("disabled")`) loopback conformance tests.

## Gate #7 baselines (Linux `x86_64` release)

Measured against stripped release builds (`lto = "thin"`, `codegen-units = 1`, `strip = true`):

| Binding / Crate | Stripped Release Size | Per-Call FFI Overhead (`device_id`) | Measurement Method |
|---|---|---|---|
| `tendril-ffi` (`--no-default-features`) | 4,052,248 bytes (3.86 MiB) | Core-only baseline | `stat -c%s` on `libtendril_ffi.so` built with `--no-default-features` |
| `tendril-ffi` (default `p2p-iroh`) | 14,606,424 bytes (13.93 MiB) | Included via Go cgo baseline | `stat -c%s` on `target/release/libtendril_ffi.so` |
| Go (`bindings/go`) | Links `libtendril_ffi.so` | 363.1 ns/op (`2,924,054` iterations in 1s) | Phase 3 `go test -run=^$ -bench=BenchmarkFFIOverhead -benchtime=1s` (`runtime.LockOSThread`) |
| Python (`bindings/python`, `lib_tendril.so`, `p2p-iroh`) | 16,270,208 bytes (15.52 MiB) | 255.2 ns/op (`100,000` calls in `0.0255s`) | `stat -c%s` on release `.so`; Phase 3 `timeit` calling `tendril.device_id(k)` |
| Node.js (`bindings/node`, `libtendril_node.so`, `p2p-iroh`) | 16,441,984 bytes (15.68 MiB) | 475.6 ns/op (`100,000` calls in `47.56ms`) | `stat -c%s` on release `.node`; Phase 3 `performance.now()` calling `deviceId(k)` |

For mobile (`aarch64-linux-android`, Swift) and browser WASM bundle budgets and Argon2id timings, see [Web and mobile bindings](web-and-mobile.md).

## Verification

Each binding verifies the four helper-level `spec/vectors/` files (`fingerprints.json`, `pairing_mac.json`, `rotation.json`, and `grants.json`) offline (while `spec/vectors/handshake.json` is verified in Rust and Go via `make vectors/check`) and runs bidirectional client/host live interop against `tendril-conformance-peer` (covering pairing, SAS confirmation, capability minting, encrypted data exchange, authorization, revocation, plus `rekey` in Python/Node bidirectional runs and Go concurrency tests):

```bash
make bindings/go      # build tendril-ffi and run Go cgo tests with -race
make bindings/python  # build _tendril.so and run Python unittest suite
make bindings/node    # build index.node and run node --test suite
make bindings/check   # run Go, Python, Node, Web WASM, and Kotlin JNI suites
make check            # run full workspace lint, Rust tests, vectors, and bindings
```

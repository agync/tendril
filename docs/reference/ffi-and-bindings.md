---
type: Reference
title: FFI ABI and cross-language bindings
description: Callback-free C ABI surface, group mesh calls, thin Go/Python/Node bindings, and Gate #7 binary size and FFI latency baselines.
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

- **Shared inbound routing (`InboundRouter`):** Peeks each incoming stream's cleartext preamble under the pre-auth rate limiter and dispatches `0x01` and `0x02` `Intent::Pair` and `Intent::Session` streams onto protocol-isolated bounded queues (`InboundQueue`s for v1/v2 pairing and sessions) with isolated half-open budgets, rate limiters, and automatic expiration (`DEFAULT_PRE_AUTH_TIMEOUT`), so unconsumed pairing floods never block or starve `accept_session` (and vice versa), while `set_pair_enabled(false)` disables and clears both v1 and v2 pair queues and `close()` wakes waiting callers immediately.
- **Durable roster persistence:** Host key rotations and rotation-fork revocations during `connect`, as well as CRL updates (including session-terminating `0x03 REVOCATION` frames), are persisted to `StateStore` across `tendril-ffi`, Python, and Node. These native `Endpoint` bindings assume single-process ownership of a `state_dir` (persisting atomic snapshots under `.roster.lock`), whereas multi-process CLI workflows (`tendril serve` paired with CLI subcommands) coordinate via transactional `StateStore::update_roster` updates and live `RosterStamp` reloads. `tendril-ffi` also exposes `tendril_endpoint_new_from_state` and `tendril_{endpoint_export_identity,endpoint_export_roster,session_export_roster}_json` for hosts that keep identity and roster in their own storage. The Kotlin and Swift bindings use `tendril_endpoint_new_sealed` instead: they keep only the identity sealed by the Keystore or Keychain (`identity.sealed`), and the runtime persists roster and group state in the same `state_dir` (see [Sealed local state](../design/groups.md#sealed-local-state)).
- **Full-duplex session concurrency:** `tendril-runtime` splits streams into `PathReader` and `PathWriter` (`PathStream::into_split`) behind `ConcurrentSession` (`reader -> writer -> machine -> roster -> pending_events` lock ordering, `shutdown()` wakeup, and fresh `current_unix_secs` reads inside `next_event_now`), so parked `poll_event` / `PollEvent` calls do not block `send_data`, `rekey`, `authorize`, or `close` / shutdown across FFI, Go, Python, and Node.
- **Go (`bindings/go`):** Links `libtendril_ffi` through cgo against `crates/tendril-ffi/include/tendril.h`, rejecting embedded NUL bytes in string parameters.
- **Python (`bindings/python`):** Builds a PyO3 `abi3-py39` extension module (`tendril._tendril`) with `unsafe_code = "forbid"`, releasing the GIL via `py.detach` around Argon2 derivation (`compute_code_mac`) and every `Endpoint`/`Session` (`Arc<ConcurrentSession>`) lock, disk I/O, or blocking runtime operation (`info_json` is a lock-free metadata serialization).
- **Node.js (`bindings/node`):** Builds a `napi-rs` N-API v8 native addon (`index.node`) with `unsafe_code = "forbid"`, validating safe non-negative integers (`0..=Number.MAX_SAFE_INTEGER`) at the JS/N-API boundary and offloading Argon2 (`computeCodeMac`) and async `Endpoint`/`ConcurrentSession` operations onto Tokio so the JS event loop stays responsive.

## C ABI surface (`crates/tendril-ffi`)

`crates/tendril-ffi/include/tendril.h` is manually maintained in lockstep with `crates/tendril-ffi/src/lib.rs`, exports key-length constants (`TENDRIL_KEY_LEN = 32`, `TENDRIL_SIGNING_PUB_LEN = 1984`, `TENDRIL_SIGNING_HASH_LEN = 32`), and defines a callback-free polled C ABI backed by a multi-threaded Tokio runtime:

| Symbol Group | Representative Functions | Ownership & Error Contract |
|---|---|---|
| Status & cleanup | `tendril_last_error`, `tendril_string_free` | Negative `TendrilResult` populates UTF-8 char-boundary truncated thread-local error buffer; heap strings returned via `char **` are zeroized and released with `tendril_string_free` |
| Vector & core helpers | `tendril_device_id`, `tendril_fingerprint_host`, `tendril_fingerprint_device`, `tendril_pairing_sas`, `tendril_compute_code_mac`, `tendril_verify_rotation_chain_json`, `tendril_verify_grant_json` | Pure delegation to `tendril-core` with early out-pointer validation and `catch_unwind` panic boundaries |
| Endpoint lifecycle | `tendril_endpoint_new`, `tendril_endpoint_new_from_state`, `tendril_endpoint_new_sealed`, `tendril_endpoint_close`, `tendril_endpoint_free`, `tendril_endpoint_info_json`, `tendril_endpoint_export_identity_json`, `tendril_endpoint_export_roster_json`, `tendril_endpoint_configure_transports_json`, `tendril_endpoint_mint_relay_ticket`, `tendril_endpoint_serve_direct`, `tendril_endpoint_serve_relay`, `tendril_endpoint_serve_relay_v2`, `tendril_endpoint_serve_p2p`, `tendril_endpoint_issue_code`, `tendril_endpoint_pair_initiate`, `tendril_endpoint_pair_v2_initiate`, `tendril_endpoint_pair_accept`, `tendril_endpoint_pair_v2_accept`, `tendril_endpoint_confirm_peer`, `tendril_endpoint_mint_grant`, `tendril_endpoint_revoke_peer`, `tendril_endpoint_add_trust_anchor`, `tendril_endpoint_revoke_trust_anchor`, `tendril_endpoint_mint_enrollment_token`, `tendril_endpoint_enroll_initiate` | Opaque `TendrilEndpoint *`; NULL or empty `state_dir` selects ephemeral in-memory operation unless `tendril_endpoint_new_from_state` supplies in-memory identity/roster JSON; `tendril_endpoint_new_sealed` takes a required `state_dir` plus caller-sealed identity JSON and lets the runtime persist roster and group state in `rt-roster.sealed` and `rt-groups.sealed`, sealed under an identity-derived key (without an identity one is generated and nothing is written, so the caller saves it and reopens with it; `roster_json_opt` needs the identity and is parsed and written only for a directory with no runtime state; existing state without an identity, another identity, or a tampered file returns NULL, see [Sealed local state](../design/groups.md#sealed-local-state)); `tendril_endpoint_configure_transports_json` configures managed relay admission, P2P relay pools/tokens, and wake providers via `TransportConfigInput` (`#[serde(deny_unknown_fields)]`, `ZeroizeOnDrop`) accepting keys: `relay_auth_secret`, `relay_ticket`, `p2p_relay_mode`, `p2p_relay_urls`, `p2p_pkarr`, `p2p_advertise_direct_addrs`, `p2p_allow_private_addrs`, `p2p_relay_auth_token`, `p2p_api_secret`, `wake_url`, `wake_adapter`, `wake_secret_b64`, `wake_auth_token`, `wake_pre_wake`, `wake_retry_delay_ms`, `wake_max_attempts`, and `wake_timeout_ms`; `tendril_endpoint_mint_relay_ticket` signs Tier 3 `RelayTicket` JSON; `tendril_endpoint_serve_relay_v2` binds a `/v2/relay` listener; `tendril_endpoint_close` wakes parked accepts before `tendril_endpoint_free`; manual `tendril_endpoint_pair_initiate` / `tendril_endpoint_pair_v2_initiate` (PAKE `0x02`) record hosts in `pending` state requiring `tendril_endpoint_confirm_peer` before `connect`; `tendril_endpoint_pair_v2_accept` accepts inbound `0x02` PAKE pairing; `tendril_endpoint_add_trust_anchor` and `tendril_endpoint_mint_enrollment_token` enable opt-in M2M enrollment acceptance with atomic nonce burning prior to response transmission; `tendril_endpoint_serve_p2p` binds a deterministic HKDF-derived `iroh` listener (`"default"`, `"disabled"`/`"local"`, or relay URL) when compiled with `p2p-iroh` |
| Session lifecycle & polling | `tendril_session_connect`, `tendril_session_connect_v2`, `tendril_session_accept`, `tendril_session_accept_v2`, `tendril_session_shutdown`, `tendril_session_free`, `tendril_session_export_roster_json`, `tendril_session_send_data`, `tendril_session_poll_event`, `tendril_session_authorize`, `tendril_session_rekey`, `tendril_session_close` | Opaque `TendrilSession *` remains valid after `tendril_endpoint_free` and supports concurrent send/authorize/poll/shutdown; `tendril_session_connect_v2` and `tendril_session_accept_v2` drive Wire `0x02` pseudonymous sessions with padded/jittered transport; `tendril_session_send_data` checks `len <= MAX_APP_DATA_LEN` before reading caller buffers; `tendril_session_poll_event` validates `out_event_json` before polling and returns `TENDRIL_OK` (`0`), `TENDRIL_WOULD_BLOCK` (`1`), or `TENDRIL_EOF` (`2`) |

### `TendrilResult` status codes

- `TENDRIL_OK` (`0`): operation succeeded.
- `TENDRIL_WOULD_BLOCK` (`1`): timed poll completed with no queued event ready.
- `TENDRIL_EOF` (`2`): peer stream ended cleanly.
- Negative codes (`TENDRIL_ERR_INVALID_ARG` `-1`, `TENDRIL_ERR_NOT_FOUND` `-2`, `TENDRIL_ERR_CLOSED` `-5`, `TENDRIL_ERR_PROTOCOL` `-6`, `TENDRIL_ERR_INTERNAL` `-7`): error details are readable via `tendril_last_error`.

## Group mesh C ABI

Small peer mesh groups ([design](../design/groups.md), `spec/groups-v1.md`) reach host languages as thin calls over `tendril-runtime` (`GroupPool`, `GroupHub`, and the admin facade). Bindings never build manifests, evaluate authorization, or see the rendezvous key or pairwise secrets. Admin calls return public manifest JSON only, and every group API needs an endpoint with a state directory (`"groups require a state directory endpoint"`, `TENDRIL_ERR_INVALID_ARG`).

| Function | Purpose |
|---|---|
| `tendril_group_create(ep, name, min_wire_version, endpoints_json, out_manifest_json)` | Root creates a group and persists manifest and secrets |
| `tendril_group_add_member(ep, group_id, peer_id, caps_json, endpoints_json, out_manifest_json)` | Add a roster peer with a known signing key (M2M-enrolled, or code-paired; peers code-paired before the signing key claim must re-pair and confirm first). Every roster entry whose stored or static-derived device id is `peer_id` counts: any revoked entry refuses the add, otherwise one `Active` entry with a signing key is used; `caps_json` and `endpoints_json` are null or a JSON array of strings |
| `tendril_group_remove_member(ep, group_id, peer_id, out_manifest_json)` | Revoke the member and rotate the rendezvous key |
| `tendril_group_ingest_manifest(ep, manifest_json, sender_peer_id, out_group_id)` | Ingest a manifest from an authenticated peer; `sender_peer_id` must be the peer that delivered it, and first-contact pinning (F11) applies |
| `tendril_group_open(ep, group_id, listen_addr, out_group)` | Open a `TendrilGroup *`; `listen_addr` may be NULL, otherwise a direct listener is bound and served |
| `tendril_group_local_endpoint(group, out_endpoint)` | Endpoint bound by `listen_addr`, or `*out_endpoint == NULL` when none |
| `tendril_group_sync(group, out_report_json)` | Admin push of manifest and rendezvous key to members; needed for Wire v2 groups |
| `tendril_group_broadcast(group, required_cap, data_ptr, data_len, out_report_json)` | Fan out to members; NULL `required_cap` means `group.send:<group_id>`; report is `{delivered, offline, failed}` with `failed` as `[device_id, error]` pairs |
| `tendril_group_poll_event(group, timeout_ms, out_event_json)` | `TENDRIL_OK` with an event, `TENDRIL_WOULD_BLOCK` on timeout, `TENDRIL_EOF` once the pool is closed; a parked poll returns `TENDRIL_EOF` promptly when the handle closes |
| `tendril_group_authorize_peer(group, peer_id, cap)` | `TENDRIL_OK` when the peer holds `cap`; any refusal sets the last error |
| `tendril_group_close(group)`, `tendril_group_free(group)` | Idempotent close, then free |

**Ownership.** Free every `char **` out string with `tendril_string_free`. `tendril_group_close` is idempotent, releases the handle's `listen_addr` listener so the port is reusable, and later calls on the handle (including `tendril_group_poll_event`) return `TENDRIL_ERR_CLOSED`; `tendril_endpoint_close` shuts down the group hub; `tendril_group_free` is safe after close and must not race with other calls on the handle. The FFI adds a p2p dialer (feature `p2p-iroh`) only when a p2p relay mode is configured explicitly or `TENDRIL_P2P_LOCAL=1` is set. The first `tendril_group_open` on an endpoint routes its inbound session streams through the group hub, so configure transports before it. Ordinary sessions still arrive through `tendril_session_accept` and `tendril_session_accept_v2`. A call already parked in either accept function when the first group opens switches to the group channels at once, and the hub registers every stored group before it handles a stream. Once groups run, `tendril_session_accept` and `tendril_session_accept_v2` apply `timeout_ms` to the whole wait for a group-routed session, including waiting behind another concurrent accept; a call that was parked on the router when the first group opened and dequeues a stream at that moment completes that stream's handshake under the pre-auth timeouts, outside `timeout_ms`.

**Python and Node.** `group_open` and `groupOpen` build a standalone `GroupPool` per call and run no hub, so inbound sibling sessions are accepted only on that group's own `listen_addr`; pass one on every member that must be dialed. With `relay_listen=True` (Python) or `relayListen: true` (Node) the pool also registers its relay mailboxes on the relay hints of its own manifest entry and accepts siblings there; pass it on the one process that serves the identity, since a relay keeps only the latest registration. The pool never registers on the relay host of a URL served with `serve_relay` (`serveRelay`) on the same endpoint (matched by host, not by exact URL or port), so the endpoint keeps that mailbox and siblings reach the group through its other endpoints. Each open reads that list once, so let every `serve_relay` call return before `group_open`: a pool opened earlier competes with a later `serve_relay` on a relay host named in the member's own entry. Relay dials and registrations use the endpoint's relay auth (`relay_auth_secret` or `relay_ticket` through `configure_transports_json` or `configureTransportsJson`). Admin onboarding also works through ordinary sessions the host accepts and polls. A p2p dialer for `iroh://` member endpoints is added only when a p2p relay mode is configured explicitly or `TENDRIL_P2P_LOCAL=1` is set, as in the FFI; other `p2p_*` settings alone never add one. `Endpoint.close` closes every group still open on the endpoint, and later calls on those groups fail with `group is closed`.

**Relay limits.** A `/v2/relay` manifest endpoint is dialed on the target's group mailbox while the current key is held; any other relay endpoint is dialed with the target's manifest `relay_pub`. The FFI group hub passes the endpoint's relay auth and registers each group's mailbox on the `/v2/relay` hints of the local member's own entry (and the identity's mailbox on its other relay hints), as `tendril serve` does, from the first `tendril_group_open`; configure transports (relay auth) first, and let every successful `tendril_endpoint_serve_relay` call return before the first `tendril_group_open`, since the hub reads the URLs served that way once, when it starts (calls that overlap the first open are not covered, and an open that starts the hub but returns no group handle still starts it), and leaves the relay hosts of those URLs (matched by host, not by exact URL or port) to the app. Hub discovery of stored groups runs only when the hub starts and on each `tendril_group_open`, and nothing retries it: a group stored later opens on the next `tendril_group_open`, and a group whose pool failed to open (for example because its root CRL could not be resolved) stays unreachable, even after the roster is repaired, until another `tendril_group_open` on that endpoint. Only a pool that did open reconciles its relay registrations on its own 250 ms tick. An admin push to a member that holds no current key reaches it over a `/v2/relay` endpoint only through its ordinary pair mailbox listener: `tendril_endpoint_serve_relay_v2`, `serve_relay_v2`, `serveRelayV2`, or `tendril serve --relay`, with the host accepting and polling the session. See [Small peer mesh groups](../design/groups.md#known-limitations).

**Error mapping.** `GroupNotFound` and unknown peers return `TENDRIL_ERR_NOT_FOUND`, a closed pool or handle returns `TENDRIL_ERR_CLOSED`, I/O and storage failures return `TENDRIL_ERR_INTERNAL`, malformed arguments (including a store-less endpoint) return `TENDRIL_ERR_INVALID_ARG`, and every other core refusal (for example `GroupUnauthorized`, `GroupSeqRollback`, `GroupManifestFork`) returns `TENDRIL_ERR_PROTOCOL`. The core error name and message are preserved in `tendril_last_error`.

**Group event JSON** (`tendril_group_poll_event`):

| `event` | Fields |
|---|---|
| `app_data` | `sender_device_id`, `payload_b64` (base64url) |
| `manifest_updated` | `seq` |
| `member_joined`, `member_revoked` | `device_id` |
| `audit` | `audit` (denied or dropped inbound action) |

**Session event JSON** (`tendril_session_poll_event`). Group frames received on an ordinary session are ingested by the runtime (`handle_session_group_frame`) on state-directory and sealed endpoints, so first-contact pinning, admin authority, and the removed-device refusal apply unchanged. The binding only reports a redacted outcome:

| `event` | Fields |
|---|---|
| `group_manifest_ingested`, `group_manifest_rejected` | `group_id`, `seq`, `error` (rejections only) |
| `group_rendezvous_ingested`, `group_rendezvous_rejected` | `group_id`, `seq`, `error` (rejections only); the key is never included |
| `group_manifest_unverified` | Store-less endpoints only: `group_id`, `seq`, `manifest_json` (input to `group_ingest_manifest`) |
| `group_rendezvous_unverified` | Store-less endpoints only: `group_id`, `seq` |

### Per-language group surface

| Operation | Go (`Endpoint`, `Group`) | Python (`Endpoint`, `Group`) | Node (`Endpoint`, `Group`) | Kotlin (`TendrilEndpoint`, `TendrilGroup`) | Swift (`TendrilEndpoint`, `TendrilGroup`) |
|---|---|---|---|---|---|
| Create | `GroupCreate` | `group_create` | `groupCreate` | `groupCreate` | `groupCreate` |
| Add member | `GroupAddMember` | `group_add_member` | `groupAddMember` | `groupAddMember` | `groupAddMember` |
| Remove member | `GroupRemoveMember` | `group_remove_member` | `groupRemoveMember` | `groupRemoveMember` | `groupRemoveMember` |
| Ingest manifest | `GroupIngestManifest` | `group_ingest_manifest` | `groupIngestManifest` | `groupIngestManifest` | `groupIngestManifest` |
| Open (optional `listen_addr`; Python and Node also `relay_listen`) | `OpenGroup` | `group_open(group_id, listen_addr=None, relay_listen=False)` | `groupOpen(groupId, listenAddr?, relayListen?)` | `openGroup` | `openGroup` |
| Local endpoint | `LocalEndpoint()` | `local_endpoint` | `localEndpoint` | `localEndpoint()` | `localEndpoint()` |
| Sync | `Sync()` | `sync()` | `sync()` | `sync()` | `sync()` |
| Broadcast | `Broadcast(data, requiredCap)` | `broadcast(data, required_cap=None)` | `broadcast(data, requiredCap?)` | `broadcast(data, requiredCap)` | `broadcast(data, requiredCap:)` |
| Poll event | `PollEvent(ms)`: `(nil, nil)` on timeout, `io.EOF` when closed | `poll_event(timeout_ms=5000)`: `None` on timeout | `pollEvent(timeoutMs?)`: `null` on timeout | `pollEvent(ms)`: `null` on timeout, throws when closed | `pollEvent(timeoutMs:)`: `nil` on timeout, throws `.eof` when closed |
| Authorize peer | `AuthorizePeer` returns an error on refusal | `authorize_peer` returns `True` or raises | `authorizePeer` returns `true` or throws | `authorizePeer` throws on refusal | `authorizePeer` throws on refusal |
| Close | `Close()` (idempotent, finalizer-safe) | `close()` and context manager; `Endpoint.close()` also closes open groups | `close()`; `Endpoint.close()` also closes open groups | `close()` (`Closeable`) | `close()` |

Create, add, and remove return manifest JSON strings and ingest returns the group id in every binding. Python, Node, Kotlin, and Swift return report and event JSON strings as-is, while Go decodes broadcast and sync reports into `BroadcastReport` and polled events into `GroupEvent` (with `Payload()` to decode `payload_b64`). Errors keep the core name and message in each binding's native type: a Go `error` carrying the FFI code, Python `RuntimeError`, a Node generic-failure `Error`, Kotlin `IllegalStateException` or `IllegalArgumentException`, and Swift `TendrilError`.

Kotlin `TendrilEndpoint.create(stateDir)` and Swift `TendrilEndpoint(stateDir:)` on Apple platforms create sealed endpoints (`tendril_endpoint_new_sealed`) and host groups like any state-directory endpoint; only endpoints without a state directory fail with the invalid-argument error above. The Kotlin and Swift group sources compile against the same header but are not verified on Linux CI. The browser has a separate member-only surface; see [Web and mobile bindings](web-and-mobile.md).

## Language bindings summary

### Go (`bindings/go`)

- Exposes size constants (`SigningPubLen = 1984`, `SigningHashLen = 32`), typed wrappers (`Endpoint`, `Session`, `EndpointInfo` including `SigningPubHash` and `RelayPub`, `PairInitiateResult`, `PairAcceptResult`, `EnrollInitiateResult`, `SessionEvent` including `Audit`, `ErrWouldBlock`), `ServeDirect`, `ServeRelay`, `ServeP2p`, M2M methods (`AddTrustAnchor` taking `1984` bytes, `RevokeTrustAnchor`, `MintEnrollmentToken`, `EnrollInitiate` accepting `1984`-byte keys or `32`-byte SHA-256 hash pins), and pure helper functions (`DeviceID`, `FingerprintHost`, `FingerprintDevice`, `PairingSAS`, `ComputeCodeMAC`, `VerifyRotationChainJSON`, `VerifyGrantJSON`).
- Guards `Endpoint` with `sync.RWMutex` (so `Close()` signals `tendril_endpoint_close` while releasing in-flight calls before taking exclusive `Lock()` to free), guards `Session` with `sync.RWMutex` + `tendril_session_shutdown` (allowing concurrent full-duplex `SendData`/`Rekey`/`PollEvent`/`Close`), validates strings against embedded NUL bytes, pairs pointer and byte-slice reads with `runtime.KeepAlive`, and pins OS threads via `runtime.LockOSThread()` / `runtime.UnlockOSThread()` around cgo calls and `tendril_last_error()` reads under `go test -race`.

### Python (`bindings/python`)

- Exposes `Endpoint` (with `info_json` returning `signing_pub`, `signing_pub_hash`, and `relay_pub`; `serve_direct`, `serve_relay` using the 32-byte Ed25519 relay prefix, `serve_p2p`, `pair_initiate`, `connect` delegating dialing internally to `tendril-runtime::dial_endpoint` for `iroh://`, `overlay://`, `broker+ws(s)://`, `ws(s)://`, local, and direct targets, plus M2M methods `add_trust_anchor` taking `1984` bytes, `revoke_trust_anchor`, `mint_enrollment_token`, and `enroll_initiate` accepting `1984`-byte keys or `32`-byte hash pins), `Session`, `device_id`, `fingerprint_host`, `fingerprint_device`, `pairing_sas`, `compute_code_mac`, `verify_rotation_chain_json`, and `verify_grant_json` from `tendril`.
- `compute_code_mac` and all blocking, mutex-acquiring, or disk-persisting `Endpoint` and `Session` methods release the GIL via `py.detach`, verified by a multi-threaded heartbeat test during concurrent `compute_code_mac` Argon2 execution, M2M replay/revocation tests, and concurrent handshake threads.

### Node.js (`bindings/node`)

- Exposes `Endpoint` (`infoJson` returning `signing_pub`, `signing_pub_hash`, and `relay_pub`), `Session` (non-constructible directly via `private constructor()` in `bindings/node/index.d.ts`), synchronous hash/verifier helpers (`deviceId`, `fingerprintHost`, `fingerprintDevice`, `pairingSas`, `verifyRotationChainJson`, `verifyGrantJson`), synchronous M2M management methods (`addTrustAnchor` taking `1984` bytes, `revokeTrustAnchor`, `mintEnrollmentToken`), and async `Promise` methods (`computeCodeMac`, `serveDirect`, `serveRelay`, `serveP2p`, `pairInitiate`, `pairAccept`, `enrollInitiate` accepting `1984`-byte keys or `32`-byte hash pins, `connect`, `acceptSession`, `sendData`, `pollEvent`, `authorize`, `rekey`, `close`).
- Verified by a `setInterval` timer responsiveness test running alongside concurrent `computeCodeMac` Argon2 promises, local P2P (`serveP2p("disabled")`) loopback tests, and M2M enrollment/replay/revocation conformance tests.

Full M2M enrollment parity (`addTrustAnchor`, `revokeTrustAnchor`, `mintEnrollmentToken`, and `enroll` / `enrollInitiate`) also extends across browser WebAssembly, Android Kotlin JNI, and Apple Swift; see [Web and mobile bindings](web-and-mobile.md).

## Gate #7 baselines (Linux `x86_64` release)

Measured against stripped release builds (`lto = "thin"`, `codegen-units = 1`, `strip = true`):

| Binding / Crate | Stripped Release Size | Per-Call FFI Overhead (`device_id`) | Measurement Method |
|---|---|---|---|
| `tendril-ffi` (`--no-default-features`, hybrid PQ) | 4,834,416 bytes (4.61 MiB) | Core-only Wave 2 PQ baseline | `stat -c%s` on `libtendril_ffi.so` built with `--no-default-features` |
| `tendril-ffi` (default `p2p-iroh`, hybrid PQ) | 15,196,176 bytes (14.49 MiB) | Included via Go cgo baseline | `stat -c%s` on `target/release/libtendril_ffi.so` |
| Go (`bindings/go`) | Links `libtendril_ffi.so` | 363.1 ns/op (`2,924,054` iterations in 1s) | Phase 3 `go test -run=^$ -bench=BenchmarkFFIOverhead -benchtime=1s` (`runtime.LockOSThread`) |
| Python (`bindings/python`, `lib_tendril.so`, `p2p-iroh`) | 16,270,208 bytes (15.52 MiB, Phase 3 pre-PQ) | 255.2 ns/op (`100,000` calls in `0.0255s`) | Phase 3 `stat -c%s` on release `.so`; Phase 3 `timeit` calling `tendril.device_id(k)` |
| Node.js (`bindings/node`, `libtendril_node.so`, `p2p-iroh`) | 16,441,984 bytes (15.68 MiB, Phase 3 pre-PQ) | 475.6 ns/op (`100,000` calls in `47.56ms`) | Phase 3 `stat -c%s` on release `.node`; Phase 3 `performance.now()` calling `deviceId(k)` |

For mobile (`aarch64-linux-android`, Swift) and browser WASM bundle budgets and Argon2id timings, see [Web and mobile bindings](web-and-mobile.md).

## Verification

Each binding verifies the helper-level `spec/vectors/` files (`fingerprints.json`, `pairing_mac.json`, `rotation.json`, and `grants.json`) offline (while `spec/vectors/handshake.json` and `spec/vectors/m2m_enrollment.json` are verified in Rust and Go via `make vectors/check`) and runs bidirectional client/host live interop against `tendril-conformance-peer` (covering pairing, SAS confirmation, M2M enrollment/replay/anchor-revocation, capability minting, encrypted data exchange, authorization, revocation, plus `rekey` in Python/Node bidirectional runs and Go concurrency tests):

```bash
make bindings/go      # build tendril-ffi and run Go cgo tests with -race
make bindings/python  # build _tendril.so and run Python unittest suite
make bindings/node    # build index.node and run node --test suite
make bindings/check   # run Go, Python, Node, Web WASM, and Kotlin JNI suites
make check            # run full workspace lint, Rust tests, vectors, and bindings
```

---
type: Design
title: Sans-I/O core state machines and path policy
description: Pure Sans-I/O design for PairingInitiator, PairingResponder, Roster, SessionMachine, and PathPlanner in tendril-core.
status: stable
tags: [design, core, sans-io, policy]
---

# Sans-I/O core state machines and path policy

`tendril-core` implements pairing, session establishment, roster state, capability enforcement, and connection path selection with `#![forbid(unsafe_code)]`, explicit virtual clocks (`now_unix`, `now_ms`), and zero async or OS I/O dependencies.

## Driver loop

Callers pump raw bytes and explicit timestamps into the state machines and drain typed action slices:

```text
bytes / commands + (now_unix, now_ms) ---> StateMachine ---> Vec<Action>
```

- `ResumableFrameReader` bounds buffered bytes at `MAX_READ_BUFFER_LEN`, decodes the 6-byte cleartext preamble first, and rejects declared outer frame lengths above `65519` before payload allocation.
- Private key scalars (`StaticKeypair`, `SigningKeypair` covering Ed25519 and ML-DSA-65 seeds), pairing codes, Argon2id outputs, pure-Rust `Noise_XXhfs` DH/KEM/cipher/chaining states (`x25519-dalek` + `fips203`), and decoded handshake/transport plaintext buffers use `zeroize` wrappers and redact secrets from `Debug` output.

## Pairing and roster trust transitions

| Component | Key Rules |
|---|---|
| `PairingManager` | Unbiased 31-char code sampling, `900 s` default TTL, `5` failed claims burn all live codes, single-use burn even when a `revoked` peer claims a live code, 2-group LAN codes rejected on `Remote` paths |
| `PairingUri` | `tendril://pair?v=1&...` codec validating scheme, version, non-zero static key, 32-byte `sh=` signing hash pin, strict query parameters, control-character absence, validated endpoint hints (at most `6`, `1,024` bytes), the relay key `rp`, and the route statement `rq` and `rs`. `PairingCodeKind::from_code` is the single code classifier. A builder (`PairingManager::issue_pairing_uri`) normalizes, validates, dedupes, caps and signs the announced route set. `verify_route_statement` returns `RouteCheck` (`Verified`, `Unsigned`, `Invalid`) and authorization reads only the immutable `VerifiedRouteStatement`. `PairRouteBinding` (the URI plus an optional operator relay key) bound to a `PairingInitiator` or `V2PakePairInitiator` enforces the URI's host pin and computes the `rp`, operator key and `rs` verdict at `msg2` (`route_verdict`), and the initiator refuses `msg3` on a failed pin or verdict, deferred or not |
| `PairingInitiator` / `PairingResponder` | Decouples `pair` (`pending`) from host `confirm_peer` and `mint_grant`; validates `HostHello.signing_pub` against optional QR `sh=` hash or full key pins before emitting `msg3` |
| `Roster` | Indexes peer entries cleanly, matches inbound `Session` peers strictly on full 32-byte `static_pub`, enforces non-zero pins (`IncompletePin`), stores `1984`-byte hybrid signing keys, transitions immediately to `revoked` on trust-root rotation forks, and ingests monotonic signed CRLs. It also stores each peer's routes with their source (`operator`, `signed`, `committed`) and `route_meta` (`seq`, `issued_at`, `origin`), merges pairing results against a high-water sequence (`merge_pair_plan`), applies signed announcements (`apply_route_announcement`), keeps the host's own persistent route sequence (`bump_local_routes`), and gates every established session on the pin (`check_established_session`) |

## Sealed session and path planner

- **`SessionMachine`:** Drives in-tree pure-Rust `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, executes the initiator `msg2` `HostHello.signing_pub` + static pin/rotation abort gate before disclosing client static keys in `msg3`, enforces `MAX_FRAME_LEN` pre-encryption so oversized plaintexts never advance nonces, checks grants via `authorize_grant` returning structured `AuditEvent` records, and automatically triggers `0x04 REKEY` at `1_048_576` sent frames or `15` minutes while re-validating grants and CRLs on `REKEY` and `0x03 REVOCATION`.
- **Route expectation and route sets:** A session initiator can carry a `RouteExpectation` (the pinned `k` and `sh`, and a relay key or recovery statement) that is checked against the chain-verified `HostHello` before `msg3`, and `with_route_seq` fixes the optional `SessionHello.route_seq` before the first byte is written. Received `0x0C ROUTE_SET` frames decode into a queue read through `take_route_sets()`; the machine adds no action variant, and the runtime applies each set to the roster under the store lock.
- **`PathPlanner`:** Orders candidates strictly by `sort_key` (`(provider.rank(), u8::from(provider == Relay && !is_v2_relay_hint), !is_numeric_host, id)`) across `local < direct < overlay < p2p < relay < broker` so `/v2/relay` always precedes `/v1/relay` even ahead of numeric hosts, staggers Happy Eyeballs probes every `250 ms`, delays cold `p2p` probing (`500 ms`) so higher rungs race unblocked, exposes `next_deadline_ms()` for host event loops, holds pinned paths for `10 s` before probing fall-up every `30 s` (preempting `/v1/relay` for `/v2/relay`), and fails over immediately on active path faults.

## Adversarial verification

In-process integration tests in `crates/tendril-core/tests/adversarial.rs` drive complete pair, confirm, mint, delegate, data, `PING`/`PONG`, frame-count and time-based auto-`REKEY`, key rotation, CRL revocation, and graceful `CLOSE` flows under 1-byte/odd-chunked I/O, frame drops/reordering/replay, bit-flips, oversized frames, cross-intent splicing, MITM handshake splicing, expired/burned pairing codes, incomplete pins, widened delegations, forged issuers, and trust-root vs. unanchored rotation forks.

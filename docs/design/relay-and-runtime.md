---
type: Design
title: Stateless relay v1 and async runtime providers
description: Design for the stateless WSS ciphertext relay (spec/relay-v1.md), pluggable path providers (local, direct, relay), 6-point provider contract, rate limiting, and atomic persistence.
status: stable
tags: [design, relay, runtime, providers]
---

# Stateless relay v1 and async runtime providers

Tendril keeps the cryptographic trust boundary inside [the Sans-I/O core](sans-io-core.md) while `tendril-relay` and `tendril-runtime` provide stateless ciphertext forwarding and concrete OS transports without modifying security invariants.

## Stateless WebSocket relay (`tendril-relay`)

`tendril-relay` implements the normative control and bridge rules in `spec/relay-v1.md` (`/v1/relay`) and `spec/relay-v2.md` (`/v2/relay`) on top of native `rustls` TLS (`wss://<host>/v1/relay` and `wss://<host>/v2/relay`, with `ws://` permitted on loopback fixtures):

1. **Challenge and anti-hijack proofs:** Every `/v1/relay` and `/v2/relay` connection starts with a JSON `challenge` containing a fresh 32-byte CSPRNG `nonce`, the relay's bound `host`, and `max_frame = 65521` (plus `epoch` on `/v2/relay`). On `/v1/relay`, listeners prove mailbox ownership using the 32-byte Ed25519 `relay_pub` prefix with strict Ed25519 signatures bound to `"tendril-relay-reg-v1\0" || host || nonce` on `register` and `"tendril-relay-accept-v1\0" || host || nonce || conn_id` on `accept`. On `/v2/relay`, listeners use hourly epoch `mailbox_id` keys and sign the `epoch`-bound `"tendril-relay-reg-v2\0"` / `"tendril-relay-accept-v2\0"` inputs defined in `spec/relay-v2.md`. Unowned `accept` attempts fail with `"unauthorized"` without removing the legitimate pending dial.
2. **Managed relay admission (Tiers 1-3 and Option 1A `--auth-scope`):** Both `/v1/relay` and `/v2/relay` support three composable stateless admission tiers (`allowlist OR proof`, not additive):
   - **Tier 1 (Allowlist):** `--allow-mailbox` / `--allow-mailboxes-file` admits matching mailbox keys on `register` and `accept` without an additional HMAC/ticket proof; an empty or comment-only file (0 valid keys) fails closed at startup. Because `/v2/relay` mailbox keys are hourly-rotating `mailbox_id`s (`spec/relay-v2.md`), Tier 1 is practical primarily for `/v1/relay`.
   - **Tier 2 (Shared HMAC):** `--auth-secret-file` or `TENDRIL_RELAY_AUTH_SECRET` verifies HMAC-SHA256 proofs over `tendril-relay-auth-v1\0`. `tendril-relay` enforces `0600` regular non-symlink file permissions on `--auth-secret-file` and `--tls-key` (in containers/Kubernetes, mount projected secrets as `0600` regular non-symlink files without symlink indirection or group/world read bits); `tendril-relay` reads `TENDRIL_RELAY_AUTH_SECRET` once at startup rather than stripping process env.
   - **Tier 3 (`RelayTicket`):** `--issuer-pub` verifies JCS-canonical Ed25519 `RelayTicket` proofs (`tendril-relay-ticket-v1\0`, `role: register | dial | any`, `1..=86400s` TTL, `+-30s` clock skew). A `RelayTicket` is a **bearer credential** if exposed in untrusted channels or logs unless scoped to `target_pub` and a short TTL.
   - **Option 1A (`--auth-scope <all|register-only>`):** Defaults to `all` whenever any admission mechanism is active so both `register` and `dial` require admission (closing `/v1/relay` and `/v2/relay` dial freeloading); under `all`, dial admission validates `auth` right after decode before mailbox lookup or epoch skew checks. Passing `--auth-scope` with no allowlist, secret, or issuer fails closed, and `--auth-scope register-only` with Tier 1 alone leaves `dial` open because Tier 1 is peer-mailbox allowlisting.
3. **Opaque binary forwarding:** Once `ready` is emitted to both sides, the relay forwards WebSocket binary frames verbatim. Non-binary frames after `ready` or frames exceeding `65521` bytes terminate both halves immediately without forwarding.
4. **Bounded resource limits:** An LRU-bounded per-IP/prefix (`/64` IPv6) token bucket (`max_tracked_ips = 4096`, with an eviction-overflow throttle) gates incoming connections. For configured `--trusted-proxy` CIDRs, trusted-proxy peers take a pre-upgrade semaphore permit (`(max_total_connections / 4).max(1)`) and run handshake upgrade under a `min(5s, accept_timeout)` timeout, extracting the client IP right-to-left using the explicitly selected `--trusted-proxy-header` (`x-forwarded-for` default or `forwarded`, preventing `Forwarded` from bypassing `X-Forwarded-For`); per-IP `ip_guard` limits apply to the extracted client IP after upgrade. Active caps enforce `max_total_connections = 4096`, `max_mailboxes = 1024`, `max_pending_per_mailbox = 8`, `max_active_per_ip = 64`, `max_active_per_mailbox = 64`, `15 s` accept timeout, `300 s` idle stream timeout, and eager flush with a `1 s` write backpressure timeout.

## Runtime providers and 6-point contract (`tendril-runtime`)

All path implementations expose the `PathStream`, `PathListener`, and `PathDialer` traits with zero cryptographic or policy logic inside transports:

| Provider | Transport | Security and Bounds |
|---|---|---|
| `local` | Unix domain sockets | `0o600` socket file permissions, `1 s` write backpressure timeout, `65521 B` outer frame ceiling |
| `direct` | TCP (`TCP_NODELAY`) | Optional IP allow-list filter, `1 s` write backpressure timeout, `65521 B` outer frame ceiling |
| `relay` | WebSocket (`/v1/relay`) | `rustls` `ring` TLS provider for `wss://`, verifies `challenge.host` and `max_frame`, signed `register` and `accept`, `1 s` write timeout |

Every built-in provider passes the 6-point contract suite in `crates/tendril-runtime/tests/provider_contract.rs`:

- `1 B` and `65519 B` (`MAX_FRAME_LEN`) frames round-trip intact.
- `64` sequential frames preserve strict FIFO order.
- Peer close is observed within `<= 2 s`.
- Slow-reader `1 s` backpressure terminates blocked writers cleanly without unbounded buffering.
- Oversized `65520 B` outer frame bodies and `65522 B` raw chunks fail closed.
- Intercepted wire bytes of a real `Noise_XXhfs` session confirm zero plaintext canary leakage.

## Pre-auth limits, state store, and policy dialing

- **`PreAuthRateLimiter` and `InboundRouter`:** Guards `InboundRouter`, `SessionDriver::accept`, and `drive_pair_responder` with partitioned trusted vs. untrusted (`Relay`/`Broker`) half-open quotas, IPv6 `/64` + unattributed buckets, per-key concurrent half-open limits, LRU eviction-overflow throttling, and RAII `HalfOpenGuard` tracking. `InboundRouter` separates `0x01` and `0x02` inbound handshakes into isolated queues and rate limiters, while `set_pair_enabled(false)` disables and clears both v1 and v2 pair queues.
- **`StateStore`:** Opens state directories with `0o700` permissions (rejecting symlinks), validates `0o600` regular-file permissions before loading keys/rosters, serializes `load_or_generate_identity` with `.identity.lock` and roster transactions with `.roster.lock`, and writes `identity.json` (`Zeroizing` wrappers) and `roster.json` via `0o600` temp-file `sync_all` + atomic rename.
- **`dial_with_policy_verified` & `SessionDriver::connect_with_policy`:** Drive `PathPlanner` over Tokio `JoinHandle`s (`local < direct < overlay < p2p < relay < broker`), gating candidate activation on Noise `HostHello` verification rather than raw TCP connect so decoy paths cannot blackhole healthy fallback paths.

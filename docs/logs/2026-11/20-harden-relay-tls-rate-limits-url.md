---
type: Log Entry
title: "Harden relay TLS, rate limits, URL safety, P2P privacy, and CLI inputs (Audit Batch 2A)"
description: "Harden relay TLS, rate limits, URL safety, P2P privacy, and CLI inputs (Audit Batch 2A)"
tags: [log, update]
kind: Update
status: stable
---

Harden core crypto zeroization and URI parsing, relay TLS and rate limits, URL safety, runtime failover and permissions, P2P privacy defaults, and CLI secret inputs (Audit Batch 2A).

- Core (`tendril-core`, `spec/`): wrap `snow` Noise DH, cipher, and hash resolvers and plaintext buffers in zeroizing wrappers, add `authorize_path` canonicalization helpers, and enforce strict `PairingUri`, `PairClaim`, and `HostHello` control-character and field validation.
- Relay and URL validation (`tendril-relay`, `tendril-runtime`, `tendril-wasm`): partition `PreAuthRateLimiter` between trusted and untrusted (`Relay`/`Broker`) streams with unattributed burst/half-open caps and per-peer caps; enforce per-`EndpointId` concurrency bounds on `P2pListener`; normalize IPv6 `/64` rate-limit buckets and eviction overflow; add native `rustls` TLS (`--tls-cert`/`--tls-key`) and `--trusted-proxy` right-to-left IP extraction to `tendril-relay`; validate WebSocket and `iroh` relay URLs and filter private `?addr=` hints on dialed endpoints.
- P2P privacy, runtime, and CLI (`tendril-runtime`, `tendril-wasm`, `tendril-cli`, `docs/`): default `P2pOptions` for `P2pRelayMode::Custom` and `P2pDialer` to `presets::Minimal` without `PkarrPublisher`, omit `?addr=` hints in `format_p2p_endpoint` by default, add Noise-gated `dial_with_policy_verified` and `SessionDriver::connect_with_policy`, enforce `DEFAULT_PRE_AUTH_TIMEOUT` in `drive_pair_initiator`, harden Unix socket binding and `StateStore` permissions/locking, and add CLI `--p2p-relay`, `--no-pkarr`, `--ephemeral-p2p`, `--include-direct-addrs`, `--code-stdin`, `--code-file`, and `TENDRIL_PAIR_CODE` support.

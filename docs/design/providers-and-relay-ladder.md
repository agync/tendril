---
type: Design
title: Six-rung path providers and relay ladder
description: Untrusted PathProvider implementations across all six Policy rungs, zero-setup iroh P2P discovery, scoped overlay IPC, embedded relays, and zero-re-pair hint migration.
status: stable
tags: [design, providers, relay, p2p, overlay, broker]
---

# Six-rung path providers and relay ladder

Tendril treats every transport path as an untrusted byte pipe below Noise XX (`Noise_XX_25519_ChaChaPoly_SHA256`). Phase 5 completes all six rungs of `ProviderId` inside `tendril-runtime` and exposes them in `tendril-cli`.

## Provider ladder and dialing policy

| Rung (`ProviderId`) | Rank | Implementation (`tendril-runtime`) | Primary Use Case |
|---|---|---|---|
| `local` | 0 | `LocalListener` / `LocalDialer` (`0o600` Unix socket) | Same-host IPC between desktop/daemon processes |
| `direct` | 1 | `DirectListener` / `DirectDialer` (TCP) | LAN or direct IP reachable sockets |
| `overlay` | 2 | `OverlayListener` / `OverlayDialer`, `OverlayHelperListener` / `OverlayHelperDialer` | Tailnet CGNAT/ULA sockets or scoped `0o600` helper IPC |
| `p2p` | 3 | `P2pListener` / `P2pDialer` (`iroh` 1.5, gated behind `p2p-iroh`) | Zero-setup NAT traversal with public relay/discovery fallback |
| `relay` | 4 | `RelayListener` / `RelayDialer`, `EmbeddedRelay` | Stateless WebSocket relay (`spec/relay-v1.md`) |
| `broker` | 5 | `BrokerListener` / `BrokerDialer` (`broker+ws://` / `broker+wss://`) | Reverse-proxied or authenticated HTTPS/WSS tunnel adapter |

`PathPlanner` (`dial_with_policy`) ranks candidates by `(provider.rank(), !is_numeric_host, id)` and enforces `p2p_cold_delay_ms` (`500 ms` default) before dialing `p2p` candidates alongside higher-priority local/direct/overlay candidates so fast local connections are never stalled by peer discovery.

## Zero-setup P2P (`p2p-iroh` feature)

Enabling `p2p-iroh` on `tendril-runtime` (enabled by default in `tendril-cli`) compiles `crates/tendril-runtime/src/providers/p2p.rs` over `iroh` 1.5 (`tls-ring`, `portmapper`):

- **Relay modes (`P2pRelayMode`):** `Default` uses `iroh::endpoint::presets::N0` for zero-configuration public relay homing and peer discovery, `Custom(url)` targets a self-hosted `iroh-relay`, and `Disabled` binds local UDP sockets using `presets::Minimal` without contacting public infrastructure.
- **Stream instantiation (`TENDRIL_P2P_ALPN = "tendril/p2p/v1"`):** Because QUIC bidirectional streams created by `open_bi()` are only surfaced on the remote `accept_bi()` after initial bytes arrive, `P2pDialer` sends a `1`-byte stream opener (`0x54`) immediately after `open_bi()`, and `P2pListener` validates it under a bounded timeout before admitting the stream.
- **Connection lifetime:** `P2pListener`, `P2pDialer`, and `P2pStream` share an `Arc<EndpointGuard>` and keep closing `Connection` handles alive briefly on drop (`250 ms` cap after `send.finish()`) so final flushed frames and QUIC `FIN` deliver cleanly.

## Relay ladder and zero-re-pair migration

Applications can move between public relays, self-hosted `tendril-relay` containers, and in-process `EmbeddedRelay` instances without discarding existing Noise pins or signed grants:

- `EmbeddedRelay::bind_local` / `EmbeddedRelay::start` embeds `tendril_relay::RelayServer` directly in-process for single-host zero-dependency relay fallback.
- `Roster::update_relay_hints` (`crates/tendril-core/src/roster.rs`) updates `entry.relay_hints` for non-revoked peers while leaving `static_pub`, `signing_pub`, `rotation_seq`, `state`, and `grants` untouched.
- Persisted `StateStore` rosters reload updated relay hints across restarts (`public -> self-hosted -> embedded`) and re-establish sessions with existing credentials (`Gate #10`).

## Scoped overlay and broker adapters

- **`overlay` (`providers/overlay.rs`):** `select_overlay_mode` evaluates `OverlayMode::{Disabled, Host, Helper, Auto}` using file or environment variable credential references (`auth_key_file` / `auth_key_env`), never inline secrets. `is_tailnet_ip` identifies `100.64.0.0/10` and `fd7a:115c:a1e0::/48` addresses. `OverlayHelperListener` and `OverlayHelperDialer` communicate solely over `0o600` Unix sockets inside `0o700` directories with bounded 1-line JSON control framing, avoiding localhost TCP port forwarding.
- **`broker` (`providers/broker.rs`):** `BrokerListener` validates exact HTTP `GET` request path (`404` mismatch) and optional request headers via `subtle::ConstantTimeEq` (`401` mismatch) under pre-auth upgrade limits before exposing a `WsBinaryPathStream` bounded by `MAX_OUTER_FRAME_LEN`.

## Verification status

- `tendril-runtime` verifies the 6-point provider contract and full Noise XX pairing/confirm/mint/data/rekey/revoke lifecycle across all six rungs (`local`, `direct`, `overlay`, `p2p`, `relay`, `broker`), `select_overlay_mode` + scoped Unix helper IPC, broker rejection paths, `p2p` cold-delay policy failover, and `public -> self-hosted -> embedded` `relay_hints` migration.
- `tendril-cli` verifies live subprocess `tendril serve --embedded-relay --p2p-local --overlay --broker` pairing over `iroh` P2P and dialing across `P2p`, `Overlay`, `Broker`, and `Relay` (`EmbeddedRelay`).
- Physical 30-minute mobile battery draw (`Gate #11`) requires dedicated iOS/Android hardware runs outside headless Linux CI.

---
type: Design
title: Six-rung path providers and relay ladder
description: Untrusted PathProvider implementations across all six Policy rungs, zero-setup iroh P2P discovery, scoped overlay IPC, embedded relays, and zero-re-pair hint migration.
status: stable
tags: [design, providers, relay, p2p, overlay, broker]
---

# Six-rung path providers and relay ladder

Tendril treats every transport path as an untrusted byte pipe below hybrid post-quantum Noise (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`). Phase 5 completes all six rungs of `ProviderId` inside `tendril-runtime` and exposes them in `tendril-cli`.

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

Enabling `p2p-iroh` on `tendril-runtime` (enabled by default in `tendril-cli` and `tendril-ffi`, and opt-in on `tendril-wasm`) compiles `crates/tendril-runtime/src/providers/p2p.rs` (native) or `crates/tendril-wasm/src/p2p.rs` (browser WASM) over `iroh` 1.5 (`tls-ring`, plus `portmapper` on native targets):

- **Relay modes (`P2pRelayMode` & `P2pOptions`):** Constructed from `iroh::endpoint::presets::Minimal`, attaching `PkarrPublisher`, `PkarrResolver`, and `DnsAddressLookup` only when explicitly enabled. `P2pRelayMode::Default` enables Pkarr lookup/publish on listeners while dialers never publish (`publish_pkarr = false`). `P2pOptions::for_endpoint` isolates `?relay=` URI hints by keeping `n0` DNS/Pkarr off and enforcing the bearer token guard when dialing custom relays (matching browser `dialIrohStream`). `parse_p2p_relay_modes` maps `--p2p-relay` (`default`, `disabled`, or `1..=8` repeatable URLs, accepting `https://` or loopback `http://`) to `Default`, `Disabled`, `Custom(String)` (`1` URL), or `CustomMany(Vec<String>)` (`2..=8` URLs), targeting validated self-hosted `iroh-relay` URLs without touching `n0` Pkarr/DNS unless `--p2p-pkarr` is opted in. On `wasm32-unknown-unknown` browsers, `WasmIrohStream` builds from `presets::Minimal` and only attaches read-only `PkarrResolver::n0_dns()` when no relay hint is provided.
- **Managed `iroh-relay` authentication (Option 2A & `p2p-iroh-services`):** Custom relay pools accept static bearer tokens via `--p2p-relay-token-file` or `TENDRIL_P2P_RELAY_TOKEN` (applied via `RelayMap::with_auth_token(...)`). Enabling the optional `p2p-iroh-services` Cargo feature (`--p2p-api-secret-file` or `TENDRIL_P2P_API_SECRET`) constructs short-lived lowercase `BASE32_NOPAD` RCAN capability tokens directly via `iroh_services::caps::create_api_token_from_secret_key` onto `Endpoint::builder(presets::Minimal)` + `RelayMap::with_auth_token(...)`, intentionally NOT calling `IrohServicesPreset::apply` (which pulls `presets::N0` Pkarr/DNS). Because `iroh` looks up `auth_token` strictly by exact relay URL key in `RelayMap`, untrusted `?relay=` hints not configured in `RelayMap` receive `auth_token = None`.
- **Address hint privacy:** `format_p2p_endpoint` omits direct `?addr=` socket hints by default (`format_p2p_endpoint_with_addrs` controls explicit opt-in), and `parse_p2p_endpoint_filtered` unconditionally strips metadata/link-local IPs and filters private/reserved `?addr=` hints on relayed dialers.
- **Deterministic P2P routing key:** Host listeners derive their `iroh::SecretKey` deterministically via single-block HKDF-SHA256 from `EndpointIdentity::static_key` (`derive_p2p_identity_seed`, label `"tendril/p2p/iroh-identity/v1"`) rather than persisting a second key file or regenerating an ephemeral `EndpointId` on every reboot (`--ephemeral-p2p` opts out). The P2P key rotates automatically whenever the static Noise key rotates, and remains routing metadata only (never an authorization input).
- **Transport PeerID pre-auth rate limiting:** `P2pStream` surfaces the remote transport `EndpointId` via `PathStream::peer_transport_id()`, so `PreAuthRateLimiter::try_acquire_for_stream` and `InboundRouter` rate-limit pre-Noise P2P handshakes per remote PeerID alongside a per-`EndpointId` concurrent accept cap on `P2pListener` (`MAX_CONCURRENT_ACCEPTS_PER_PEER = 4`) instead of starving unrelated peers.
- **Stream instantiation (`TENDRIL_P2P_ALPN = "tendril/p2p/v1"`):** Because QUIC bidirectional streams created by `open_bi()` are only surfaced on the remote `accept_bi()` after initial bytes arrive, dialers send a `1`-byte stream opener (`0x54`) immediately after `open_bi()`, and `P2pListener` validates it under a bounded timeout before admitting the stream.
- **Connection lifetime:** `P2pListener`, `P2pDialer`, and `P2pStream` share an `Arc<EndpointGuard>` with explicit `close_now()` teardown in `P2pStream::close()` and `P2pDialer::close()` so flushed QUIC frames and `FIN` deliver cleanly before runtime shutdown.

## Relay ladder and zero-re-pair migration

Applications can move between public relays, self-hosted `tendril-relay` containers (including Option 1A Tiers 1-3 admission with `--allow-mailbox` / `--allow-mailboxes-file`, `--auth-secret-file` / `TENDRIL_RELAY_AUTH_SECRET`, `--issuer-pub` + `RelayTicket`, and `--auth-scope <all|register-only>` across `/v1/relay` and `/v2/relay`), and in-process `EmbeddedRelay` instances without discarding existing Noise pins or signed grants:

- `EmbeddedRelay::bind_local` / `EmbeddedRelay::start` embeds `tendril_relay::RelayServer` directly in-process for single-host zero-dependency relay fallback.
- `RelayV2Listener` handles single-mailbox `/v2/relay` control sockets with CSPRNG-jittered reconnect backoffs and CSPRNG-jittered control pings (`22.5s..=37.5s`), and canonicalizes relay hosts via `canonical_relay_host` (handling IPv6, trailing dots, and mixed case) while preserving raw host strings for v1 HMAC compatibility; `tendril serve` (`sync_v2_relay_listeners` in `tendril-cli`) binds `/v2/relay` listeners only for `PeerState::Active` peers with staggered multi-peer bind jitter.
- `Roster::update_relay_hints` (`crates/tendril-core/src/roster.rs`) updates `entry.relay_hints` for non-revoked peers while leaving `static_pub`, `signing_pub`, `rotation_seq`, `state`, and `grants` untouched.
- Persisted `StateStore` rosters reload updated relay hints across restarts (`public -> self-hosted -> embedded`) and re-establish sessions with existing credentials (`Gate #10`).

## Scoped overlay and broker adapters

- **`overlay` (`providers/overlay.rs`):** `select_overlay_mode` evaluates `OverlayMode::{Disabled, Host, Helper, Auto}` using file or environment variable credential references (`auth_key_file` / `auth_key_env`), never inline secrets. `is_tailnet_ip` identifies `100.64.0.0/10` and `fd7a:115c:a1e0::/48` addresses. `OverlayHelperListener` and `OverlayHelperDialer` communicate solely over `0o600` Unix sockets inside `0o700` directories with bounded 1-line JSON control framing, avoiding localhost TCP port forwarding.
- **`broker` (`providers/broker.rs`):** `BrokerListener` validates exact HTTP `GET` request path (`404` mismatch) and optional request headers via `subtle::ConstantTimeEq` (`401` mismatch) under pre-auth upgrade limits before exposing a `WsBinaryPathStream` bounded by `MAX_OUTER_FRAME_LEN`.

### External overlay, Tailscale DERP, and edge-proxy topologies

| Deployment Topology | Rung & Configuration | Who Needs Overlay Client | Relay & Protocol Behavior |
|---|---|---|---|
| **Peer-to-peer on a tailnet** | `overlay` (`overlay://<tailnet_ip>:<port>` or `0o600` `tsnet` helper socket) | Both peers | `tailscaled` or `tsnet` attempts direct WireGuard UDP and falls back automatically to Tailscale's DERP relay fleet; Tendril still runs `Noise_XXhfs` and default-deny grants inside the stream |
| **Host on tailnet, external browsers or phones** | `relay` (`tailscale funnel <port>` -> standalone `tendril-relay --listen 127.0.0.1:<port> --host <node>.<tailnet>.ts.net --trusted-proxy 127.0.0.1/32`; `--embedded-relay --relay-host <node>.<tailnet>.ts.net` binds an ephemeral `127.0.0.1:0` port without `--trusted-proxy`) or native `broker` (`tendril serve --broker 127.0.0.1:<port>`) | Host only | Funnel terminates TLS at Tailscale's edge and traverses DERP to the host; `/v1/relay` and `/v2/relay` serve both `@tendril-sdk/web` browsers and native clients (verifying `challenge.host`), while `broker+wss://` serves native `BrokerDialer` clients (or custom sans-I/O WASM WebSocket wrappers) |
| **Cloudflare Tunnel, Caddy, or Nginx ingress** | `relay` (`tendril-relay --listen 127.0.0.1:<port> --host <public_host> --trusted-proxy <CIDR>`) or native `broker` (`broker+wss://`) | Neither | Edge proxy terminates TLS and forwards binary WebSockets to `tendril-relay` (browser + native) or `BrokerListener` (native `BrokerDialer`, optional constant-time header secret) |
| **Raw `derp*.tailscale.com` URL in `--p2p-relay` or `--relay`** | Unsupported | N/A | `iroh-relay` (`p2p`) diverged from Tailscale's `Upgrade: DERP` X25519 packet protocol onto WebSockets and Ed25519 node keys, `tendril-relay` speaks `/v1/relay` and `/v2/relay` JSON challenges, and Tailscale's public DERP fleet admits coordinated tailnet nodes only |

## Verification status

- `tendril-runtime` verifies the 6-point provider contract, deterministic HKDF-derived `P2pListener` `EndpointId` persistence and rotation, `peer_transport_id` pre-auth rate limiting, and full `Noise_XXhfs` pairing/confirm/mint/data/rekey/revoke lifecycle across all six rungs (`local`, `direct`, `overlay`, `p2p`, `relay`, `broker`), `select_overlay_mode` + scoped Unix helper IPC, broker rejection paths, `p2p` cold-delay policy failover, and `public -> self-hosted -> embedded` `relay_hints` migration.
- `tendril-cli` verifies live subprocess `tendril serve --embedded-relay --p2p-local --overlay --broker` pairing over `iroh` P2P, identical `iroh://<endpoint_id>` across host restarts, clean client endpoint shutdown, and dialing across `P2p`, `Overlay`, `Broker`, and `Relay` (`EmbeddedRelay`).
- `bindings/web` (`TENDRIL_WEB_P2P_LIVE=1 node bindings/web/test/browser_e2e.mjs`) verifies headless Chrome WASM (`WasmIrohStream` over `ws_stream_wasm` + `PkarrResolver::n0_dns()`) pairing and dialing a live `tendril serve --p2p` host using a bare `iroh://<endpoint_id>` URI over public `iroh-relay` WebSockets.
- Physical 30-minute mobile battery draw (`Gate #11`) requires dedicated iOS/Android hardware runs outside headless Linux CI.

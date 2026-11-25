---
type: Design
title: Six-rung path providers and relay ladder
description: Untrusted PathProvider implementations across all six Policy rungs, zero-setup iroh P2P discovery, scoped overlay IPC, embedded relays, and legacy hint migration.
status: stable
tags: [design, providers, relay, p2p, overlay, broker, routes]
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

`PathPlanner` (`dial_with_policy`) ranks candidates by `sort_key` (`(provider.rank(), u8::from(provider == Relay && !is_v2_relay_hint), !is_numeric_host, id)`), prioritizing `/v2/relay` ahead of `/v1/relay`, exposes `next_deadline_ms()`, and enforces `p2p_cold_delay_ms` (`500 ms` default) before dialing `p2p` candidates alongside higher-priority local/direct/overlay candidates so fast local connections are never stalled by peer discovery.

## Route-driven dialing

Pairing URIs, stored routes and host announcements all feed one candidate builder in `tendril-runtime` (`providers/hints.rs`), so the ladder above runs on every Day-2 connect without a caller-supplied endpoint. See [Seamless pairing defaults](../usage/seamless-pairing.md) for the user view and `spec/pairing-v1.md` Section 6 for the rules.

| Stage | Rule |
|---|---|
| Candidates | A peer's stored routes, each hint once, plus the signed hints of a recovery URI. An explicit operator endpoint replaces them. Legacy `relay_hints` are never dialed. |
| Egress | Every URI, `signed` and `committed` hint passes the egress policy at dial time. Blocked addresses (unspecified, multicast, link-local, cloud metadata) are never dialed. Hostnames are resolved once, every answer is checked, and the connect uses the checked address, so TLS name and `Host` header are unchanged. `direct:` accepts IP literals only. Loopback is allowed. Every dropped hint is reported with a reason. |
| Path class | A two-group LAN code is dialed only on candidates whose provider is `local` or `direct` and whose checked addresses are loopback or private LAN. Everything else is remote. |
| Iroh hints | URI and stored `iroh://` hints use a dedicated dialer with no Pkarr or DNS address lookup and only relays that belong to the dialer's configured relay map. A hint relay outside the map is dropped with `iroh_relay_not_configured`. Group dialers keep their own options. |
| Operator iroh | An explicit `iroh://` endpoint or a stored `operator` route keeps the operator dialer and its own options, with the always-blocked set applied inside it. Blocked `addr=` literals and literal `relay=` hosts are removed and every other parameter is kept as given; an endpoint left with only blocked destinations is skipped as `blocked_address`. Each `relay=` host name is resolved once, with the same resolver and checks as every other hint. A relay whose lookup fails or returns a blocked address is removed, and the endpoint is skipped when none is left. The checked addresses are pinned: the dialer answers those names only from the pins, through a custom iroh DNS resolver that screens every other answer, and keeps the pins for every later dial, so a rebinding answer or a resolver bypass cannot steer the connect. |
| Pkarr and DNS lookup | Off for URI and stored `signed` or `committed` iroh hints. Only the operator dialer honours an explicit choice: `--p2p-pkarr` and `--no-pkarr` on the CLI, and `p2p_pkarr` in the transport configuration of the C ABI and the Python and Node bindings. Without a choice the endpoint's default applies. |
| `/v2/relay` | Never dialed during pairing. A stored `/v2/relay` route is a Day-2 candidate only for the connected peer's own active entry, with `v2_secrets`, from an `operator` or `signed` route, on a Wire v2 driver. |
| IPC | `local:` and `unix://` hints from a URI are dropped (`ipc_from_uri`). IPC stays an operator endpoint feature. |
| Credentials | Relay tickets and shared-secret proofs are attached only to origins in `relay_auth_origins` (byte-equal scheme, host and port) or to the explicit endpoint of the call. A relay learned from a URI, route or announcement that demands authentication fails with `relay_auth_unconfigured` and the race continues. |

On the host side, `tendril-runtime` builds the announced route set from listeners that actually serve the pairing path. SDK and FFI hosts add enumerated LAN and overlay addresses (`advertise: auto`); the CLI uses concrete binds and `--advertise-endpoint` only. A `RouteAnnouncer` persists a monotonic sequence, signs each changed set, and sends it as `0x0C ROUTE_SET` to live sessions whose client opted in.

## Zero-setup P2P (`p2p-iroh` feature)

Enabling `p2p-iroh` on `tendril-runtime` (enabled by default in `tendril-cli` and `tendril-ffi`, and opt-in on `tendril-wasm`) compiles `crates/tendril-runtime/src/providers/p2p.rs` (native) or `crates/tendril-wasm/src/p2p.rs` (browser WASM) over `iroh` 1.5 (`tls-ring`, plus `portmapper` on native targets):

- **Relay modes (`P2pRelayMode` & `P2pOptions`):** Constructed from `iroh::endpoint::presets::Minimal`, attaching `PkarrPublisher`, `PkarrResolver`, and `DnsAddressLookup` only when explicitly enabled. `P2pRelayMode::N0Public` (n0's public relays, run by n0 computer together with `dns.iroh.link`; this is the default) enables Pkarr lookup/publish on listeners while dialers never publish (`publish_pkarr = false`). `P2pOptions::for_hint_dialer` dials URI hints and stored non-operator `iroh://` hints with no Pkarr or DNS lookup and relay-map filtering, while `P2pOptions::for_endpoint` serves only explicit operator endpoints and stored `operator` routes, keeping `n0` DNS/Pkarr off and enforcing the bearer token guard when dialing custom relays (matching browser `dialIrohStream`). `parse_p2p_relay_modes` maps `--p2p-relay` (`default`, with the alias `n0`, both meaning n0's public relays; `disabled`; or `1..=8` repeatable URLs, accepting `https://` or loopback `http://`) to `N0Public`, `Disabled`, `Custom(String)` (`1` URL), or `CustomMany(Vec<String>)` (`2..=8` URLs), targeting validated self-hosted `iroh-relay` URLs without touching `n0` Pkarr/DNS unless `--p2p-pkarr` is opted in. On `wasm32-unknown-unknown` browsers, `WasmIrohStream` builds from `presets::Minimal`. A hint dial (a URI hint or a stored `signed` or `committed` route) attaches no address lookup and dials through the relays of `p2pRelayUrls` or, when unset, the n0 public relay map, keeping only hint relays in that map. Only an explicit operator dial that names no relay attaches the read-only `PkarrResolver::n0_dns()` lookup.
- **Managed `iroh-relay` authentication (Option 2A & `p2p-iroh-services`):** Custom relay pools accept static bearer tokens via `--p2p-relay-token-file` or `TENDRIL_P2P_RELAY_TOKEN` (applied via `RelayMap::with_auth_token(...)`). Enabling the optional `p2p-iroh-services` Cargo feature (`--p2p-api-secret-file` or `TENDRIL_P2P_API_SECRET`) constructs short-lived lowercase `BASE32_NOPAD` RCAN capability tokens directly via `iroh_services::caps::create_api_token_from_secret_key` onto `Endpoint::builder(presets::Minimal)` + `RelayMap::with_auth_token(...)`, intentionally NOT calling `IrohServicesPreset::apply` (which pulls `presets::N0` Pkarr/DNS). Because `iroh` looks up `auth_token` strictly by exact relay URL key in `RelayMap`, untrusted `?relay=` hints not configured in `RelayMap` receive `auth_token = None`.
- **Address hint privacy:** `format_p2p_endpoint` omits direct `?addr=` socket hints by default (`format_p2p_endpoint_with_addrs` controls explicit opt-in), and `parse_p2p_endpoint_filtered` unconditionally strips metadata/link-local IPs and filters private/reserved `?addr=` hints on relayed dialers.
- **Deterministic P2P routing key:** Host listeners derive their `iroh::SecretKey` deterministically via single-block HKDF-SHA256 from `EndpointIdentity::static_key` (`derive_p2p_identity_seed`, label `"tendril/p2p/iroh-identity/v1"`) rather than persisting a second key file or regenerating an ephemeral `EndpointId` on every reboot (`--ephemeral-p2p` opts out). The P2P key rotates automatically whenever the static Noise key rotates, and remains routing metadata only (never an authorization input).
- **Transport PeerID pre-auth rate limiting:** `P2pStream` surfaces the remote transport `EndpointId` via `PathStream::peer_transport_id()`, so `PreAuthRateLimiter::try_acquire_for_stream` and `InboundRouter` rate-limit pre-Noise P2P handshakes per remote PeerID alongside a per-`EndpointId` concurrent accept cap on `P2pListener` (`MAX_CONCURRENT_ACCEPTS_PER_PEER = 4`) instead of starving unrelated peers.
- **Stream instantiation (`TENDRIL_P2P_ALPN = "tendril/p2p/v1"`):** Because QUIC bidirectional streams created by `open_bi()` are only surfaced on the remote `accept_bi()` after initial bytes arrive, dialers send a `1`-byte stream opener (`0x54`) immediately after `open_bi()`, and `P2pListener` validates it under a bounded timeout before admitting the stream.
- **Connection lifetime:** `P2pListener`, `P2pDialer`, and `P2pStream` share an `Arc<EndpointGuard>` with explicit `close_now()` teardown in `P2pStream::close()` and `P2pDialer::close()` so flushed QUIC frames and `FIN` deliver cleanly before runtime shutdown.

### Sockets a P2P endpoint opens

Every `P2pListener` and `P2pDialer` is one `iroh` endpoint and opens the sockets below. Only the QUIC UDP rows open whatever the relay mode; the relay and Pkarr rows depend on the mode and options. Each long-lived bind (listeners, the hint dialer, group dialers) logs one `p2p endpoint bound` line at `info` level, and each per-dial bind for an explicit endpoint logs it at `debug`. The line names the relays, whether it publishes to Pkarr, the address lookup, port mapping, and the bind addresses (relay hosts redacted, hidden entirely for relays taken from a peer URI, no tokens or paths).

| Socket | When it opens | Controlled by |
| --- | --- | --- |
| UDP IPv4 QUIC socket (also carries QUIC address discovery to relays) | At bind, `0.0.0.0:0` by default (`AllInterfaces`) | `P2pOptions::bind_addrs` |
| UDP IPv6 QUIC socket | At bind, `[::]:0` by default (`AllInterfaces`), best effort (failure is ignored) | `P2pOptions::bind_addrs` |
| Port mapping: UPnP discovery multicast (SSDP, `239.255.255.250:1900`) and NAT-PMP/PCP datagrams to the gateway (UDP 5351) from short-lived UDP sockets | At bind for listeners and dialers alike, then again on each network report that has a relay map. Needs an IPv4 QUIC socket with a non-zero port | `P2pOptions::port_mapping` (on by default) |
| Relay TCP/TLS WebSocket connection and the network-report HTTPS probes (`/generate_204`, latency GET) to each relay | When the relay map is non-empty (`N0Public`, `Custom`, `CustomMany`) | `P2pRelayMode` |
| DNS lookups for relay host names | When the relay map is non-empty; operator endpoints answer from pinned addresses | `P2pRelayMode` |
| n0 address lookup: DNS queries to `dns.iroh.link` and Pkarr HTTPS reads from `dns.iroh.link/pkarr` | When `resolve_pkarr` is on and the endpoint is not the hint dialer | `P2pOptions::resolve_pkarr` |
| Pkarr HTTPS publish to `dns.iroh.link/pkarr` | When `publish_pkarr` is on and the endpoint is not the hint dialer (listeners only in the defaults) | `P2pOptions::publish_pkarr` |

`bind_addrs` binds only the QUIC UDP sockets. It does not bind or restrict the relay TCP connections, DNS lookups, or the port mapping sockets. `P2pBindAddrs::Only { v4, v6 }` binds exactly the given sockets and none for a family left `None`, so a loopback-only bind limits direct UDP to loopback. It does not make the endpoint local-only: relay TCP/TLS connections, Pkarr and DNS lookups, and port mapping still apply unless the relay mode is `Disabled` and `port_mapping` is off. With no IPv4 socket the port mapping never starts. Relay mode `Disabled` and port mapping are independent: a `Disabled` endpoint still probes the gateway unless `port_mapping` is off. `P2pListener::bound_sockets` and `P2pDialer::bound_sockets` return the bound addresses.

## Relay ladder and legacy hint migration

Applications can move between public relays, self-hosted `tendril-relay` containers (including Option 1A Tiers 1-3 admission with `--allow-mailbox` / `--allow-mailboxes-file`, `--auth-secret-file` / `TENDRIL_RELAY_AUTH_SECRET`, `--issuer-pub` + `RelayTicket`, and `--auth-scope <all|register-only>` across `/v1/relay` and `/v2/relay`), and in-process `EmbeddedRelay` instances without discarding existing Noise pins or signed grants. Rosters that predate multi-route pairing keep their hints for display only: they must re-pair, apply a signed URI, or pass an explicit endpoint, because `relay_hints` are never auto-dialed:

- `EmbeddedRelay::bind_local` / `EmbeddedRelay::start` embeds `tendril_relay::RelayServer` directly in-process for single-host zero-dependency relay fallback.
- For hosted multi-device relays without managing VPS state directly, see the [private relay hosting guide](../usage/relay-hosting.md) covering the hibernatable Cloudflare Workers Durable Object (`deploy/cloudflare/`), PaaS container templates, Oracle Cloud Always Free, and Tailscale Funnel.
- `RelayV2Listener` handles single-mailbox `/v2/relay` control sockets with CSPRNG-jittered reconnect backoffs and CSPRNG-jittered control pings (`22.5s..=37.5s`), and canonicalizes relay hosts via `canonical_relay_host` (handling IPv6, trailing dots, and mixed case) while preserving raw host strings for v1 HMAC compatibility; `tendril serve` (`sync_v2_relay_listeners` in `tendril-cli`) binds `/v2/relay` listeners only for `PeerState::Active` peers with staggered multi-peer bind jitter.
- `Roster::update_relay_hints` (`crates/tendril-core/src/roster.rs`) updates `entry.relay_hints` for non-revoked peers while leaving `static_pub`, `signing_pub`, `rotation_seq`, `state`, and `grants` untouched. `relay_hints` is display data kept for older rosters: Day-2 auto-dial uses the peer's `routes` (see [Route-driven dialing](#route-driven-dialing)), which survive the same migrations.
- Persisted `StateStore` rosters reload updated relay hints across restarts (`public -> self-hosted -> embedded`) and re-establish sessions with existing credentials (`Gate #10`).

## Scoped overlay and broker adapters

- **`overlay` (`providers/overlay.rs`):** `select_overlay_mode` evaluates `OverlayMode::{Disabled, Host, Helper, Auto}` using file or environment variable credential references (`auth_key_file` / `auth_key_env`), never inline secrets. `is_tailnet_ip` identifies `100.64.0.0/10` and `fd7a:115c:a1e0::/48` addresses. `OverlayHelperListener` and `OverlayHelperDialer` communicate solely over `0o600` Unix sockets inside `0o700` directories with bounded 1-line JSON control framing, avoiding localhost TCP port forwarding.
- **`broker` (`providers/broker.rs`):** `BrokerListener` validates exact HTTP `GET` request path (`404` mismatch) and optional request headers via `subtle::ConstantTimeEq` (`401` mismatch) under pre-auth upgrade limits before exposing a `WsBinaryPathStream` bounded by `MAX_OUTER_FRAME_LEN`.

### External overlay, Tailscale DERP, and edge-proxy topologies

| Deployment Topology | Rung & Configuration | Who Needs Overlay Client | Relay & Protocol Behavior |
|---|---|---|---|
| **Peer-to-peer on a tailnet** | `overlay` (`overlay://<tailnet_ip>:<port>` or `0o600` `tsnet` helper socket) | Both peers | `tailscaled` or `tsnet` attempts direct WireGuard UDP and falls back automatically to Tailscale's DERP relay fleet; Tendril still runs `Noise_XXhfs` and default-deny grants inside the stream |
| **Host on tailnet, external browsers or phones** | `relay` (`tailscale funnel <port>` -> standalone `tendril-relay --listen 127.0.0.1:<port> --host <node>.<tailnet>.ts.net --trusted-proxy 127.0.0.1/32`; `--embedded-relay --relay-host <node>.<tailnet>.ts.net` binds an ephemeral `127.0.0.1:0` port without `--trusted-proxy`) or `broker` (`tendril serve --broker 127.0.0.1:<port>`) | Host only | Funnel terminates TLS at Tailscale's edge and traverses DERP to the host; `/v1/relay` and `/v2/relay` serve both `@tendril-sdk/web` browsers and native clients (verifying `challenge.host`), while `broker+wss://` (and loopback or `allowInsecureWs` `broker+ws://`) serves both native `BrokerDialer` and `@tendril-sdk/web` `dialBrokerStream` clients |
| **Cloudflare Tunnel, Caddy, or Nginx ingress** | `relay` (`tendril-relay --listen 127.0.0.1:<port> --host <public_host> --trusted-proxy <CIDR>`) or `broker` (`broker+wss://`) | Neither | Edge proxy terminates TLS and forwards binary WebSockets to `tendril-relay` (browser + native) or `BrokerListener` (native `BrokerDialer` + browser `dialBrokerStream`, optional constant-time header secret) |
| **Raw `derp*.tailscale.com` URL in `--p2p-relay` or `--relay`** | Unsupported | N/A | `iroh-relay` (`p2p`) diverged from Tailscale's `Upgrade: DERP` X25519 packet protocol onto WebSockets and Ed25519 node keys, `tendril-relay` speaks `/v1/relay` and `/v2/relay` JSON challenges, and Tailscale's public DERP fleet admits coordinated tailnet nodes only |

## Verification status

- `tendril-runtime` verifies the 6-point provider contract, deterministic HKDF-derived `P2pListener` `EndpointId` persistence and rotation, `peer_transport_id` pre-auth rate limiting, and full `Noise_XXhfs` pairing/confirm/mint/data/rekey/revoke lifecycle across all six rungs (`local`, `direct`, `overlay`, `p2p`, `relay`, `broker`), `select_overlay_mode` + scoped Unix helper IPC, broker rejection paths, `p2p` cold-delay policy failover, and `public -> self-hosted -> embedded` `relay_hints` migration.
- `tendril-cli` verifies live subprocess `tendril serve --embedded-relay --p2p-local --overlay --broker` pairing over `iroh` P2P, identical `iroh://<endpoint_id>` across host restarts, clean client endpoint shutdown, and dialing across `P2p`, `Overlay`, `Broker`, and `Relay` (`EmbeddedRelay`).
- `bindings/web` (`node bindings/web/test/browser_e2e.mjs` and `TENDRIL_WEB_P2P_LIVE=1 node bindings/web/test/browser_e2e.mjs`) verifies headless Chrome WASM Happy Eyeballs multi-route fallback, `broker+ws://` transport against `tendril-conformance-peer` `serve_broker`, `/v2/relay` over `/v1/relay` preference in `connectV2`, and `WasmIrohStream` over `ws_stream_wasm` pairing with a live `tendril serve --p2p` host through the `iroh://` hint of its pairing URI (no address lookup, Default relay map) and then dialing its bare `iroh://<endpoint_id>` endpoint (`PkarrResolver::n0_dns()` lookup) over public `iroh-relay` WebSockets.
- Physical 30-minute mobile battery draw (`Gate #11`) requires dedicated iOS/Android hardware runs outside headless Linux CI.

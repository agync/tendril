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
| `local` | 0 | `LocalListener` / `LocalDialer` (`0o600` Unix socket on Unix, owner-only named pipe with a same-user server check on Windows) | Same-host IPC between desktop/daemon processes |
| `direct` | 1 | `DirectListener` / `DirectDialer` (TCP), `WtListener` / `WtDialer` (opt-in `webtransport` QUIC/HTTP3 `wt://`) | LAN or direct IP reachable sockets (and browser-capable QUIC with `?certhash=`) |
| `overlay` | 2 | `OverlayListener` / `OverlayDialer`, `OverlayHelperListener` / `OverlayHelperDialer` (helper IPC is Unix only) | Tailnet CGNAT/ULA sockets or scoped `0o600` helper IPC |
| `p2p` | 3 | `P2pListener` / `P2pDialer` (`iroh` 1.5, gated behind `p2p-iroh`) | Zero-setup NAT traversal with public relay/discovery fallback |
| `relay` | 4 | `RelayListener` / `RelayDialer`, `EmbeddedRelay` | Stateless WebSocket relay (`spec/relay-v1.md`) |
| `broker` | 5 | `BrokerListener` / `BrokerDialer` (`broker+ws://` / `broker+wss://`) | Reverse-proxied or authenticated HTTPS/WSS tunnel adapter |

`PathPlanner` (`dial_with_policy`) ranks candidates by `sort_key` (`(u8::from(!operator), provider.rank(), source_tier, u8::from(provider == Relay && !is_v2_relay_hint), !is_numeric_host, id)`, where `source_tier` is `0` for `operator` and `signed`, `1` for `committed` and `2` for no stored source), prioritizing `/v2/relay` ahead of `/v1/relay`, exposes `next_deadline_ms()`, and enforces `p2p_cold_delay_ms` (`500 ms` default) before dialing `p2p` candidates alongside higher-priority local/direct/overlay candidates so fast local connections are never stalled by peer discovery.

## Route-driven dialing

Pairing URIs, stored routes and host announcements all feed one candidate builder in `tendril-runtime` (`providers/hints.rs`), so the ladder above runs on every Day-2 connect without a caller-supplied endpoint. See [Seamless pairing defaults](../usage/seamless-pairing.md) for the user view and `spec/pairing-v1.md` Section 6 for the rules.

| Stage | Rule |
|---|---|
| Candidates | A peer's stored routes, each hint once, plus the signed hints of a recovery URI. An explicit operator endpoint replaces them. Legacy `relay_hints` are never dialed. |
| Egress | Every URI, `signed` and `committed` hint passes the egress policy at dial time. Blocked addresses (unspecified, multicast, link-local, cloud metadata) are never dialed. Hostnames are resolved once, every answer is checked, and the connect uses the checked address, so TLS name and `Host` header are unchanged. `direct:` accepts IP literals only; `wt://` pins resolved addresses via a custom `DnsResolver` and verifies `?certhash=` (or native certs when omitted). Loopback is allowed. Every dropped hint is reported with a reason. |
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
- **In-band WebRTC DataChannel upgrade (`webrtc/v1`):** On non-`P2p` sessions whose `HostHello.upgrade` / `SessionHello.upgrade` intersection includes `"webrtc/v1"` (omitted when Wire v2 padding is disabled), authenticated `0x0D PATH_UPGRADE` messages exchange SDP offers and answers over the existing Noise session (at most 4 offers per session), establish a `"tendril/v1"` ordered binary DataChannel (`str0m` on native hosts behind the `webrtc` feature with concrete host ICE candidates, WebRTC in browsers with default `iceServers: []`), complete a fresh `Noise_XXhfs` session handshake pinned to the authenticated peer identity over the DataChannel, and cut over atomically.

### Sockets a P2P endpoint opens

Every `P2pListener` and `P2pDialer` is one `iroh` endpoint and opens the sockets below. Only the QUIC UDP rows open whatever the relay mode; the relay and Pkarr rows depend on the mode and options. Each long-lived bind (listeners and shared group dialers) logs one `p2p endpoint bound` line at `info` level, and each per-dial bind (for an explicit endpoint or an ephemeral hint dialer) logs it at `debug`. The line names the relays, whether it publishes to Pkarr, the address lookup, port mapping, and the bind addresses (relay hosts redacted, hidden entirely for relays taken from a peer URI, no tokens or paths).

| Socket | When it opens | Controlled by |
| --- | --- | --- |
| UDP IPv4 QUIC socket (also carries QUIC address discovery to relays) | At bind, `0.0.0.0:0` by default (`AllInterfaces`) | `P2pOptions::bind_addrs` |
| UDP IPv6 QUIC socket | At bind, `[::]:0` by default (`AllInterfaces`), best effort (failure is ignored) | `P2pOptions::bind_addrs` |
| Port mapping: UPnP discovery multicast (SSDP, `239.255.255.250:1900`) and NAT-PMP/PCP datagrams to the gateway (UDP 5351) from short-lived UDP sockets | At bind and on each network report that has a relay map. Needs an IPv4 QUIC socket with a non-zero port | `P2pOptions::port_mapping` (`true` on standard desktop listeners; `false` on mobile/`low_power` listeners and all dialers) |
| Relay TCP/TLS WebSocket connection and the network-report HTTPS probes (`/generate_204`, latency GET) to each relay | When the relay map is non-empty (`N0Public`, `Custom`, `CustomMany`) | `P2pRelayMode` |
| DNS lookups for relay host names | When the relay map is non-empty; operator endpoints answer from pinned addresses | `P2pRelayMode` |
| n0 address lookup: DNS queries to `dns.iroh.link` and Pkarr HTTPS reads from `dns.iroh.link/pkarr` | When `resolve_pkarr` is on and the endpoint is not the hint dialer | `P2pOptions::resolve_pkarr` |
| Pkarr HTTPS publish to `dns.iroh.link/pkarr` | When `publish_pkarr` is on and the endpoint is not the hint dialer (listeners only in the defaults) | `P2pOptions::publish_pkarr` |

`bind_addrs` binds only the QUIC UDP sockets. It does not bind or restrict the relay TCP connections, DNS lookups, or the port mapping sockets. `P2pBindAddrs::Only { v4, v6 }` binds exactly the given sockets and none for a family left `None`, so a loopback-only bind limits direct UDP to loopback. It does not make the endpoint local-only: relay TCP/TLS connections, Pkarr and DNS lookups, and port mapping still apply unless the relay mode is `Disabled` and `port_mapping` is off. With no IPv4 socket the port mapping never starts. Relay mode `Disabled` and port mapping are independent: a `Disabled` endpoint still probes the gateway unless `port_mapping` is off. `P2pListener::bound_sockets` and `P2pDialer::bound_sockets` return the bound addresses.

Every surface sets `port_mapping` and `bind_addrs` on each listener, dialer, group dialer and hint dialer it builds:

| Surface | Port mapping off | Bind addresses |
| --- | --- | --- |
| CLI (`serve`, `pair`, `enroll`, `dial`, `group`) | `--p2p-no-port-mapping` | `--p2p-bind <addr>`, repeatable, at most one IPv4 and one IPv6 (`0.0.0.0:0`, `[::]:0`); a family left out gets no socket |
| C ABI, Python, Node transport JSON | `"p2p_port_mapping": false` (Node also `p2pPortMapping`) | `"p2p_bind_addrs": ["0.0.0.0:0", "[::]:0"]` (Node also `p2pBindAddrs`) |

An address that does not parse, or a second address of one family, is a configuration error that names the flag or key (`--p2p-bind`, `p2p_bind_addrs`); it never falls back to all interfaces. The relay mode of every surface accepts `n0` as an alias of `default` (n0's public relays). Swift and Kotlin set `p2p_port_mapping` and `p2p_bind_addrs` with `configureP2p`.

## Relay ladder and legacy hint migration

Applications can move between public relays, self-hosted `tendril-relay` containers (including Option 1A Tiers 1-3 admission with `--allow-mailbox` / `--allow-mailboxes-file`, `--auth-secret-file` / `TENDRIL_RELAY_AUTH_SECRET`, `--issuer-pub` + `RelayTicket`, and `--auth-scope <all|register-only>` across `/v1/relay` and `/v2/relay`), and in-process `EmbeddedRelay` instances without discarding existing Noise pins or signed grants. Rosters that predate multi-route pairing keep their hints for display only: they must re-pair, apply a signed URI, or pass an explicit endpoint, because `relay_hints` are never auto-dialed:

- **`RelayV2Listener` and `PowerProfile` (`Standard` vs `LowPower`):** `RelayV2Listener` adapts its `/v2/relay` control sockets, keepalive schedule, standby pools, and `PathPolicyConfig` to the endpoint's `PowerProfile` (`Standard` default on desktop/server, `LowPower` default on mobile OS targets and `.extension` profiles):

| Setting | `PowerProfile::Standard` | `PowerProfile::LowPower` |
|---|---|---|
| `/v2/relay` control sockets | 3 (`epoch - 1`, `epoch`, `epoch + 1`) | 1 mid-hour (`epoch`), 2 inside `+-120 s` hour-boundary overlap via boundary sleep timers |
| Control ping cadence (`CoalescedPingScheduler`) | Independent per-call jitter `22.5 s..=37.5 s` (v1 and v2) | Coalesced `55 s..=75 s` (v1 and v2) within `90 s` client / `300 s` relay idle window |
| Standby acceptor pool | `STANDBY_POOL_SIZE = 2` on center epoch / `/v1/relay` | `0` standby sockets |
| Happy Eyeballs & fall-up policy (`PathPolicyConfig`) | `max_in_flight = 4`, `p2p_cold_delay_ms = 500`, fall-up `30 s` | `max_in_flight = 2`, `p2p_cold_delay_ms = 750`, fall-up `120 s`, LKG `preferred` affinity |
| P2P NAT port mapping & dialer lifetime | Listener `p2p_port_mapping` default `true` (desktop); dialer `p2p_port_mapping` default `false`; per-dial ephemeral hint dialer (`LazyHintP2pDialer`) and ref-tracked group `P2pDialer` | Listener and dialer `p2p_port_mapping` default `false`; per-dial ephemeral hint dialer and ref-tracked group `P2pDialer` |

- **Candidate filtering and reachability:** `check_hint` evaluates route egress checks concurrently (`join_all`) and filters direct/LAN/overlay candidates against `LocalReachability::from_snapshot` (allowing `Loopback` and matching non-loopback targets by available local IPv4/IPv6 address family with `UnreachableInterface`; link-local addresses stay rejected by `BlockedAddress`). Each Day-2 race keeps Last-Known-Good route affinity (`preferred: true` on `CandidateEndpoint`, cleared on stored connect failure, `set_peer_routes`/`clear_peer_routes`, or applied `apply_route_uri`) so the winning route leads the next reconnect without redundant parallel PQ handshakes.
- `EmbeddedRelay::bind_local` / `EmbeddedRelay::start` embeds `tendril_relay::RelayServer` directly in-process for single-host zero-dependency relay fallback.
- For hosted multi-device relays without managing VPS state directly, see the [private relay hosting guide](../usage/relay-hosting.md) covering the hibernatable Cloudflare Workers Durable Object (`deploy/cloudflare/`), PaaS container templates, Oracle Cloud Always Free, and Tailscale Funnel.
- `tendril serve` (`sync_v2_relay_listeners_with_profile` in `tendril-cli`) binds `/v2/relay` listeners only for `PeerState::Active` peers with staggered multi-peer bind jitter and the configured `PowerProfile`.
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

## Wire v2 and ephemeral P2P options

Beyond persistent v1 `iroh://<id>` listeners, Tendril supports privacy-preserving P2P listeners and split socket defaults:

- **`iroh://v2` (`--p2p-v2` / `serve_p2p_v2`):** Derives hourly rotating Ed25519 `EndpointId`s from each paired peer's `mailbox_secret` (`+-300 s` hour-boundary overlap), disables `Pkarr`, forbids `?addr=` direct address hints, and opens fresh ephemeral random dialer keys per outbound dial (no `OnceCell` dialer reuse). Configured `?relay=` hints present in the dialer's `relay_map` are tried before remaining `relay_map` entries.
- **Ephemeral Day-1 P2P (`p2p_ephemeral` / `--ephemeral-p2p`):** Generates a fresh random keypair on `serve_p2p` listeners and forces `Pkarr` off (unless `p2p_pkarr` is explicitly set) so Day-1 listeners avoid leaking a long-lived `EndpointId` or directory entry.
- **Split `port_mapping` defaults (D5):** Desktop/server `Standard` listeners keep UPnP/NAT-PMP/PCP mapping `true` by default (`power_profile.p2p_port_mapping_default() && default_p2p_listener_port_mapping()`), whereas `LowPower` or mobile (`ios`/`android`) listeners and all P2P dialers default to `false` (`default_p2p_dialer_port_mapping()`), overridable with `--p2p-port-mapping` or `p2p_port_mapping`.

## Verification status

- `tendril-runtime` verifies the 6-point provider contract, deterministic HKDF-derived `P2pListener` `EndpointId` persistence and rotation, `peer_transport_id` pre-auth rate limiting, and full `Noise_XXhfs` pairing/confirm/mint/data/rekey/revoke lifecycle across all six rungs (`local`, `direct`, `overlay`, `p2p`, `relay`, `broker`), `select_overlay_mode` + scoped Unix helper IPC, broker rejection paths, `p2p` cold-delay policy failover, and `public -> self-hosted -> embedded` `relay_hints` migration.
- `tendril-cli` verifies live subprocess `tendril serve --embedded-relay --p2p-local --overlay --broker` pairing over `iroh` P2P, identical `iroh://<endpoint_id>` across host restarts, clean client endpoint shutdown, and dialing across `P2p`, `Overlay`, `Broker`, and `Relay` (`EmbeddedRelay`).
- `bindings/web` (`node bindings/web/test/browser_e2e.mjs` and `TENDRIL_WEB_P2P_LIVE=1 node bindings/web/test/browser_e2e.mjs`) verifies headless Chrome WASM Happy Eyeballs multi-route fallback, `broker+ws://` transport against `tendril-conformance-peer` `serve_broker`, `/v2/relay` over `/v1/relay` preference in `connectV2`, and `WasmIrohStream` over `ws_stream_wasm` pairing with a live `tendril serve --p2p` host through the `iroh://` hint of its pairing URI (no address lookup, Default relay map) and then dialing its bare `iroh://<endpoint_id>` endpoint (`PkarrResolver::n0_dns()` lookup) over public `iroh-relay` WebSockets.
- Physical 30-minute mobile battery draw (`Gate #11`) requires dedicated iOS/Android hardware runs outside headless Linux CI.

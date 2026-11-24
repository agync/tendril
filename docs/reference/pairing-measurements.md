---
type: Reference
title: Pairing URI measurements
description: Measured pairing URI sizes and QR versions for realistic route sets, signed and unsigned, and a two host real network check of the LAN, overlay and relay ladder and of signed route updates.
status: stable
tags: [reference, pairing, qr, measurements, routes]
---

# Pairing URI measurements

This page records how large issued pairing URIs are for realistic route sets, which QR version they need, and how the route ladder and signed route updates behave on a real network. Normative limits live in `spec/pairing-v1.md` (Section 6). The behaviour is described in [Seamless pairing defaults](../usage/seamless-pairing.md).

## Size targets

| Limit | Value | Meaning |
|---|---|---|
| Hard bound | 1,024 bytes | Maximum encoded URI. A larger URI is rejected by the parser. QR Version 26 at error correction M. |
| Soft target | 711 bytes | QR Version 21 at error correction M, byte mode. The builder reports `uri_len` and `qr_version_m` and never drops hints to meet it. |

QR byte capacity at error correction M for the versions seen below:

| Version | Modules per side | Byte capacity |
|---|---|---|
| 10 | 57 | 213 |
| 12 | 65 | 287 |
| 13 | 69 | 331 |
| 16 | 81 | 450 |
| 17 | 85 | 504 |
| 18 | 89 | 560 |
| 19 | 93 | 624 |
| 21 | 101 | 711 |
| 26 | 121 | 1,059 |

## Method

Each row issues a URI with `tendril serve --issue-code auto` and reads `uri_len` and `qr_version_m` from the `listening` line. A fresh identity is initialised for every row. The server binds `0.0.0.0:0` and every route is passed with `--advertise-endpoint`, so the addresses are synthetic and the host never has to own them. Signed rows use the default. Unsigned rows add `--no-route-signature`. The host name is `host-a` unless stated.

| Placeholder | Synthetic value |
|---|---|
| LAN 1 | `direct:192.168.1.20:7000` |
| LAN 2 | `direct:10.0.0.20:7000` |
| Overlay | `overlay://100.64.0.7:7000` |
| Relay (short) | `wss://relay.example.net/v1/relay` |
| Relay (long) | `wss://relay.home.example.org/v1/relay` |
| Relay v2 | `wss://relay.example.net/v2/relay` |
| P2P (bare) | `iroh://` followed by a 64 character hex key |
| P2P (with relay) | the bare form plus `?relay=https://relay.example.net/` |

## Results

| Route set | Hints | Signed bytes | Signed version | Unsigned bytes | Unsigned version | Signed within 711 |
|---|---|---|---|---|---|---|
| LAN 1 (short code) | 1 | 285 | 12 | 190 | 10 | yes |
| LAN 1, overlay, relay (short) | 3 | 414 | 16 | 319 | 13 | yes |
| LAN 1, overlay, relay (long) | 3 | 419 | 16 | 324 | 13 | yes |
| LAN 1, LAN 2, overlay, relay (short), P2P (bare) | 5 | 518 | 18 | 423 | 16 | yes |
| LAN 1, LAN 2, overlay, relay (long), P2P (with relay) | 5 | 568 | 19 | 473 | 17 | yes |
| LAN 1, LAN 2, overlay, relay (long), P2P (with relay), relay v2 | 6 | 611 | 19 | 516 | 18 | yes |
| As the five hint row above, host name `living-room-media-server-01` | 5 | 610 | 19 | 515 | 18 | yes |

Every row stays under the soft target and far under the hard bound. The largest signed URI is 611 bytes, which leaves 100 bytes below Version 21 and 413 bytes below the hard bound.

## What drives the size

| Factor | Cost |
|---|---|
| Route signature (`rq` and `rs`) | 95 bytes in every row, independent of the route set |
| Long code (any non LAN route) instead of the short code | 5 bytes |
| Host name | 2 bytes per character, because the name is carried twice |
| Direct hint such as `direct:192.168.1.20:7000` | 29 bytes with its separator, since the colons are percent encoded |
| P2P hint with a relay parameter | 45 bytes more than the bare form |

A realistic six hint signed URI was estimated at about 700 bytes. The measured six hint URI with short synthetic names is 611 bytes. Longer relay and host names use the remaining 100 bytes of headroom below Version 21 at one byte per character, and the URI crosses to Version 22 above 711 bytes.

## Scan reliability

Scan success rates were not measured here. They need a screen and a printed 40 mm code scanned 20 times per size with Android and iOS test devices. Until they exist, the 711 byte soft target stays as written, and a Version 21 success rate below 95 percent is the trigger to revisit it.

## Real network check

Two hosts on one tailnet and one home LAN ran the CLI: a Linux host served and a macOS host paired and dialed. Both ran a debug build of the same commit. Nothing was typed after the pairing URI was handed to the client, and every dial ran without `--endpoint`.

Method:

1. The host advertised, in order, a LAN address, an overlay address and a relay, with `--issue-code auto`.
2. The client ran `pair --pairing-uri` on the issued URI, then the host confirmed the client and minted a grant.
3. The client ran `dial --target host-a` three times. The first dial applies the host's route set once.
4. Times are the wall clock of the whole client process on the client host, including start up. Pairing time also includes the key exchange work.

An unreachable LAN or overlay address is one that no host owns, so connects time out and the ladder moves on. A reachable LAN address is the serving host's real LAN address, since both hosts share one LAN.

The relay was a stock `tendril-relay` on the serving host bound to loopback. The CLI refuses cleartext `ws://` off loopback, and a publicly trusted certificate for a private tailnet name would publish that name, so the relay hint was a loopback address reached through an SSH remote forward whose transport ran over the tailnet. The relay rung therefore measures the relay protocol and the ladder, not a TLS hop.

### The route ladder

| Scenario | LAN hint | Overlay hint | Winner | Pair (ms) | Dial 1, 2, 3 (ms) |
|---|---|---|---|---|---|
| Away | unreachable | reachable `100.x.y.z` | Overlay | 677 | 528, 440, 445 |
| Home | reachable `192.168.a.b` | reachable `100.x.y.z` | Direct | 332 | 104, 75, 93 |
| Overlay also down | unreachable | unreachable | Relay | 973 | 718, 706, 705 |

In every scenario the URI carried three signed routes, `route_check` was `verified`, all three routes were stored, and `skipped` was empty. The Direct dials set the process overhead at roughly 75 to 105 ms. The Overlay dials add about 350 ms and the Relay dials about 610 ms, which is the 250 ms stagger per rung plus the handshake cost on the slower paths.

### A signed route update

The host advertised a LAN address, an overlay address and the relay, then stopped. It restarted with the same state directory and new LAN and overlay ports, with the relay unchanged. The client was not re-paired.

| Step | Result |
|---|---|
| Pairing | Direct, three signed routes stored, route sequence 1 |
| Dial before the move | Direct, 87 ms |
| Host restart | Route sequence 2, both direct ports changed |
| Dial 1 after the move | Relay, 723 ms. The stale overlay route failed with connection refused. `route_set` was `applied` with sequence 2. |
| Stored routes after dial 1 | The new LAN and overlay addresses and the relay, `route_meta` sequence 2, `origin` `session` |
| Dial 2 after the move | Direct to the new LAN address, 92 ms, no failures, `route_set` empty |

### Not covered

Phone checks were not run here: pairing on home Wi-Fi with an SDK host in `advertise: auto` mode, leaving Wi-Fi with a VPN on, turning the VPN off, and a DHCP change while connected. The Android instrumentation tests `addressChangePropagatesAndReconnects` and `networkCallbackRefreshesRoutes` and the Swift route tests cover the address change path in code, and the CLI check above covers the ladder across two real hosts.

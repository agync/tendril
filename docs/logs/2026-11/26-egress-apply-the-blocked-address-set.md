---
type: Log Entry
title: "egress: apply the blocked-address set to relay, broker and iroh dials"
description: "egress: apply the blocked-address set to relay, broker and iroh dials"
tags: [log, update]
kind: Update
status: stable
---

egress: apply the blocked-address set to relay, broker and iroh dials

- The default WebSocket address policy of the relay, `/v2/relay` and broker dialers and of the relay listeners' bind now refuses every `Blocked` destination: Teredo `2001::/32`, local-use NAT64 `64:ff9b:1::/48`, site-local `fec0::/10`, multicast, `240.0.0.0/4` and IPv4 embeddings of metadata addresses. Loopback, LAN and overlay relays stay allowed.
- A direct iroh dial drops `addr=` hints in that set even with `allow_private_addrs`, and the custom relay URL and resolved relay host checks refuse it.
- `DirectDialer`, `OverlayDialer` and so `dial_endpoint` resolve a target once through the egress policy and connect only to checked addresses, so a blocked literal or a host name with a blocked answer is refused. Overlay host names no longer use an unchecked system lookup.
- `DirectListener`, `OverlayListener`, `BrokerListener` and `WtListener` refuse to bind a specific address in the blocked set; `0.0.0.0` and `::` stay allowed.
- Every iroh endpoint now installs a pinned DNS resolver. The relay host addresses checked at bind and on each dial (including per-dial `?relay=` hosts) are pinned for five minutes, and other lookups drop blocked answers and, for a relay checked without private allowance, non-public answers.
- Without `allow_private_addrs`, IPv6 forms embedding loopback, LAN or CGNAT addresses (NAT64, 6to4, IPv4-translated, IPv4-compatible) are refused as iroh `addr=` hints and relay addresses, and the endpoint formatter omits every blocked address.

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

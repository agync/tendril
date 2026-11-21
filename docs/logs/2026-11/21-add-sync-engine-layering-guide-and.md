---
type: Log Entry
title: "Add sync-engine layering guide and Tailscale DERP topology notes"
description: "Add sync-engine layering guide and Tailscale DERP topology notes"
tags: [log, update]
kind: Update
status: stable
---

Add sync-engine layering guide and Tailscale DERP topology notes.

- Added [Layering CRDT, sync, and group engines](../../usage/layering-sync-engines.md) and linked it from [the usage index](../../usage/index.md), covering single-transport process boundaries, `<= 65,499 B` cross-version chunking across Wire v1 and Wire v2, capability-gated replication directions, and outer post-quantum vs. inner classical group-key threat boundaries.
- Added an external overlay, Tailscale DERP, Funnel, and edge-proxy deployment topology table to [Six-rung path providers and relay ladder](../../design/providers-and-relay-ladder.md).

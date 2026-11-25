---
type: Log Entry
title: "usage: add private relay hosting guide and PaaS probes"
description: "Document self-hosted relay options (PaaS containers, Tailscale Funnel, Oracle Cloud Always Free) alongside tendril-relay PaaS env config and plain HTTP /healthz probes."
tags: [log, creation]
kind: Creation
status: stable
---

# usage: add private relay hosting guide and PaaS probes

- Added [Private relay hosting and deployment](../../usage/relay-hosting.md) covering single-instance PaaS setups (Render, Fly.io `--ha=false`, Railway), Oracle Cloud Always Free, Tailscale Funnel, and relay admission tiers.
- Documented `TENDRIL_RELAY_LISTEN`, `PORT`, `TENDRIL_RELAY_HOST`, platform hostname auto-detection, and plain HTTP `GET`/`HEAD /healthz` behavior across `spec/relay-v1.md`, `spec/relay-v2.md`, [Reference CLI, relay deployment, and conformance peer](../../usage/cli-demo.md), and [Stateless relay v1 and async runtime providers](../../design/relay-and-runtime.md).

---
type: Log Entry
title: "usage: add Cloudflare Workers relay and complete hosting guide"
description: Add a hibernatable SQLite Durable Object relay backed by tendril-core WASM under deploy/cloudflare/ and complete the single-entry private relay hosting guide.
tags: [log, update, relay, cloudflare, wasm, docs]
kind: Update
status: stable
---

Implemented a Cloudflare Workers and SQLite-backed Durable Object relay under `deploy/cloudflare/` (`TendrilRelay`) powered by `tendril-core` cryptographic and protocol verification helpers exposed through `tendril-wasm`.

- Moved stateless relay constants and v1 registration/acceptance/init-frame helpers into `tendril-core::relay_auth` and exported thin WASM server verifiers in `tendril-wasm`.
- Implemented `/v1/relay`, `/v2/relay`, `/healthz`, Option 1A Tiers 1 to 3 admission without presence leaks, `standby` pools, `fast_open` `init_frame` handling, SQLite `pending_init_frames` spillover for non-`fast_open` classic fallback, `bridgeId`-isolated frame routing, and hibernatable alarm multiplexing.
- Added hibernation/security unit tests (`node:sqlite`), live `wrangler dev --local` (`workerd`) E2E tests against `TendrilWebClient` and `tendril-conformance-peer`, CI wiring (`make relay/cloudflare`, `scripts/ci-areas.sh`, `.github/workflows/ci.yml`), and Track 1 Cloudflare Workers onboarding with a `Deploy to Cloudflare` button in [Private relay hosting and deployment](../../usage/relay-hosting.md).

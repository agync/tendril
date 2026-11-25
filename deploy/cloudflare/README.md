# Tendril Relay for Cloudflare Workers

Stateless Tendril `/v1/relay` and `/v2/relay` WebSocket relay running inside a Cloudflare Worker backed by a single SQLite-backed Durable Object (`TendrilRelay`) with the WebSocket Hibernation API and `tendril-core` cryptographic verification compiled to WebAssembly.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/agync/tendril/tree/main/deploy/cloudflare)

## What it does

- Serves `/v1/relay` and `/v2/relay` WebSocket upgrades plus plain HTTP `GET` and `HEAD` `/healthz` probes.
- Runs all Ed25519 challenge-response proofs, Option 1A HMAC and JCS capability ticket verification, host canonicalization, `/v2/relay` epoch skew checks, and `init_frame` validation inside `tendril-core` WASM.
- Builds automatically in standalone **Deploy to Cloudflare** forks (`scripts/build.sh` compiles `tendril-wasm` from `agync/tendril` when invoked outside a workspace checkout, or reuses prebuilt `@tendril-sdk/web` WASM once published).
- Supports `fast_open` (`init_frame`) and `standby` pools (`MAX_STANDBY_PER_MAILBOX = 4`) via WebSocket hibernation so idle registered listeners do not consume wall-clock duration charges.
- Stores only oversized classic-fallback `init_frame` blobs transiently in SQLite (`new_sqlite_classes`) while keeping socket attachments compact.

## Deploy with Wrangler

```bash
cd deploy/cloudflare
npm ci
npx wrangler secret put TENDRIL_RELAY_AUTH_SECRET # optional Tier 2 shared secret
npx wrangler deploy
```

Set `TENDRIL_RELAY_HOST` only if requests reach the Worker through a custom domain whose internal `request.url` hostname differs from the canonical hostname clients verify. Leave `TENDRIL_RELAY_AUTH_SECRET`, `TENDRIL_RELAY_ISSUER_PUBS`, and `TENDRIL_RELAY_ALLOW_MAILBOXES` unset for an open personal relay, or configure Tiers 1 to 3 per [the private relay hosting guide](../../docs/usage/relay-hosting.md).

## Cloudflare Workers Free plan limits

- Uses `new_sqlite_classes` so SQLite-backed Durable Objects work on Cloudflare Free plans.
- Free plans allow 100,000 Worker and Durable Object requests per day, where incoming WebSocket messages count at a 20:1 request ratio while idle hibernated listener sockets consume no request or duration quota.
- All endpoints share one global Durable Object instance so listener mailboxes and dial requests meet in memory. Maximum binary frame size is 65,521 bytes.

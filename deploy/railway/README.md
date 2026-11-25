# Tendril Relay on Railway

Deploy `tendril-relay` as a single-replica container service on Railway using `ghcr.io/agync/tendril-relay:latest`.

## Setup

1. Create a new Railway service from Docker image `ghcr.io/agync/tendril-relay:latest`.
2. Add environment variable `TENDRIL_RELAY_AUTH_SECRET` (or `${{secret(32)}}` in a reusable Railway template).
3. Enable public HTTP networking on the service and set healthcheck path to `/healthz` with `1` replica (`railway.json`).

`tendril-relay` reads Railway's injected `PORT` and `RAILWAY_PUBLIC_DOMAIN` automatically, exposing `wss://<domain>/v1/relay` and `wss://<domain>/v2/relay`. Keep replicas at `1` because mailbox state is stored in process memory.

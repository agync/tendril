# Tendril Relay on Fly.io

Run a single-machine `tendril-relay` instance from the prebuilt OCI image `ghcr.io/agync/tendril-relay:latest`.

## Why `--ha=false` matters

`tendril-relay` holds registered mailboxes in process memory. Always run exactly one machine (`--ha=false` during launch, or `fly scale count 1`) so incoming dials always land on the same instance as the registered listener.

## Deploy

```bash
fly launch --copy-config --ha=false --no-deploy
fly secrets set TENDRIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
fly deploy --ha=false
```

`tendril-relay` automatically reads `FLY_APP_NAME` to set `--host <app>.fly.dev` and checks `/healthz` on port `8443`. Your relay endpoints are:

- `wss://<app>.fly.dev/v1/relay`
- `wss://<app>.fly.dev/v2/relay`

Pin `ghcr.io/agync/tendril-relay:vX.Y.Z` in `fly.toml` before running unattended production upgrades.

## Cost note

`min_machines_running = 1` keeps long-lived WebSocket control connections open continuously on one `shared-cpu-1x` (`256 MB`) machine rather than disconnecting idle listeners. See [the relay hosting guide](../../docs/usage/relay-hosting.md) for zero-cost serverless options.

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

`min_machines_running = 1` keeps long-lived WebSocket control connections open continuously on one `shared-cpu-1x` (`256 MB`, ~USD 2/mo) machine rather than disconnecting idle listeners. Under the Fly.io Free plan, personal organizations receive a $1 one-time credit for 7 days without a card, or $5/mo of usage allowance once a card is added (which covers one single-machine relay, though exceeding $5 in a month automatically moves the organization to Pay As You Go and bills the entire month from the first cent). See [the relay hosting guide](../../docs/usage/relay-hosting.md) for zero-card serverless options.

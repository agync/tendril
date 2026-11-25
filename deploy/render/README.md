# Tendril Relay on Render

Deploy `tendril-relay` from `ghcr.io/agync/tendril-relay:latest` using the Render Blueprint in `render.yaml`.

`tendril-relay` automatically binds `0.0.0.0:$PORT`, uses `RENDER_EXTERNAL_HOSTNAME` for challenge binding, generates `TENDRIL_RELAY_AUTH_SECRET`, and answers Render HTTP probes on `/healthz`.

## Free plan behavior

Render Free web services spin down after 15 minutes with no inbound traffic and cold-start on the next connection. That works best when paired with LAN, overlay, or peer-to-peer routes plus Wire v2 wake hints. For persistent always-on listener sockets, switch `plan` in `render.yaml` to `starter` (always one instance: `numInstances: 1`).

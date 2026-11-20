---
type: Guide
title: Reference CLI, relay deployment, and conformance peer
description: End-to-end guide for driving Tendril identity, pairing, grants, relayed sessions, standalone tendril-relay, and the JSON stdio conformance peer.
status: stable
tags: [usage, cli, relay, conformance]
---

# Reference CLI, relay deployment, and conformance peer

`tendril-cli` ships two binaries built on [the stateless relay and async runtime](../design/relay-and-runtime.md): `tendril` for interactive host and client administration, and `tendril-conformance-peer` for cross-language protocol test harnesses.

## Running a standalone relay

Launch `tendril-relay` locally or build the rootless container defined in `crates/tendril-relay/Containerfile`:

```bash
cargo run -p tendril-relay -- --listen 127.0.0.1:8443 --host localhost
```

In production deployments, terminate TLS (`wss://<host>/v1/relay`) at your reverse proxy or load balancer and match `--host` to the canonical public hostname verified in `register` and `accept` signatures. Because `tendril-relay` keys its per-IP token bucket and active connection limit (`max_active_per_ip = 64`) off the TCP peer address, preserve client source IPs via TLS passthrough or configure proxy connection limits accordingly.

## Endpoint lifecycle with `tendril`

Each endpoint isolates its `0o700` state directory containing `0o600` `identity.json` and `roster.json` files:

```bash
# 1. Initialize host and client identities
tendril --state-dir ./host-state init --host-id my-host
tendril --state-dir ./cli-state init

# 2. Start host listener (direct TCP, optional relay/embedded-relay/p2p/overlay/broker, and pairing code)
tendril --state-dir ./host-state serve --listen 127.0.0.1:0 --issue-code lan

# Optional multi-rung host serving (zero-setup P2P or embedded relay):
# tendril --state-dir ./host-state serve --p2p --embedded-relay --issue-code remote
# tendril --state-dir ./host-state serve --p2p-local --overlay 127.0.0.1:0 --broker 127.0.0.1:0 --issue-code remote
# (Pass --p2p-local on pair/dial when connecting to a --p2p-local endpoint offline.)

# 3. Pair client using printed endpoint and code, then record matching SAS
tendril --state-dir ./cli-state pair --endpoint 127.0.0.1:PORT --code TND-XXXX-XXXX

# 4. Confirm peer (default deny) and mint scoped capability grant on host
tendril --state-dir ./host-state confirm <client_device_id> --sas "<sas>"
tendril --state-dir ./host-state mint <client_device_id> --cap fs.read

# 5. Connect, send data, verify liveness via encrypted PING/PONG, then revoke
tendril --state-dir ./cli-state dial --target my-host --endpoint 127.0.0.1:PORT \
  --grant '<grant_json>' --message "hello-tendril"
tendril --state-dir ./host-state revoke <client_device_id>
```

Once revoked, subsequent `dial` attempts fail closed on the host listener during session establishment.

## JSON stdio conformance peer (`tendril-conformance-peer`)

Cross-language SDK bindings spawn `tendril-conformance-peer` and exchange single-line JSON commands over `stdin`/`stdout` (`stdout` is flushed after every response):

| Command | Purpose |
|---|---|
| `init` | Initialize in-memory or `state_dir`-backed identity and roster |
| `serve_direct`, `serve_relay` | Bind direct TCP or relay WSS listener onto background accept queue |
| `issue_code` | Issue single-use LAN or remote pairing code |
| `pair` | Run initiator (`endpoint` + `code`) or responder pairing exchange |
| `confirm`, `mint`, `revoke` | Transition peer state and mint default-deny signed grants |
| `connect`, `send`, `recv`, `rekey`, `close` | Drive Noise XX session, data exchange, key ratchet, and close |
| `authorize` | Evaluate capability check and return structured `AuditEvent` |
| `shutdown` | Close active listeners/session cleanly and exit |

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

In production deployments, terminate TLS directly on `tendril-relay` (`--tls-cert` and `--tls-key`, serving `wss://<host>/v1/relay`) or behind a trusted reverse proxy configured with `--trusted-proxy <CIDR>`. Right-to-left RFC 7239 `Forwarded` (falling back to `X-Forwarded-For` if absent) extraction runs only when the TCP peer matches `--trusted-proxy`, so reverse proxies should strip or overwrite untrusted client forwarding headers. Rate limits normalize IPv4-mapped addresses and group IPv6 addresses by `/64` prefix alongside global `--max-connections` and `--max-mailboxes` caps.

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
# tendril --state-dir ./host-state serve --p2p-relay https://relay.example/ --ephemeral-p2p
# tendril --state-dir ./host-state serve --p2p-local --overlay 127.0.0.1:0 --broker 127.0.0.1:0 --issue-code remote
# (Pass --p2p-local or TENDRIL_P2P_LOCAL=1 on serve/pair/dial for offline local P2P;
#  custom --p2p-relay URLs disable n0 Pkarr/DNS publishing by default; pass --no-pkarr on default relay mode
#  to opt out of Pkarr/DNS, or --include-direct-addrs to explicitly include non-metadata ?addr= hints.)

# 3. Pair client using printed endpoint and code (prefer --code-stdin, --code-file, or TENDRIL_PAIR_CODE
#    over --code in multi-user environments), then confirm SAS on both host and client
tendril --state-dir ./cli-state pair --endpoint 127.0.0.1:PORT --code-stdin <<< "TND-XXXX-XXXX"

# 4. Confirm peer on host and host pin on client (default deny; --sas is required unless passing --allow-no-sas), then mint scoped grant
tendril --state-dir ./host-state confirm <client_device_id> --sas "<sas>"
tendril --state-dir ./cli-state confirm my-host --sas "<sas>"
# Out-of-band fingerprint-only override:
# tendril --state-dir ./host-state confirm <client_device_id> --allow-no-sas
tendril --state-dir ./host-state mint <client_device_id> --cap fs.read

# 5. Connect, send data, verify liveness via encrypted PING/PONG, then revoke
tendril --state-dir ./cli-state dial --target my-host --endpoint 127.0.0.1:PORT \
  --grant '<grant_json>' --message "hello-tendril"
tendril --state-dir ./host-state revoke <client_device_id>
```

## Headless M2M enrollment and log redaction

Autonomous devices enroll without SAS interaction using `serve --allow-enroll`, single-use enrollment tokens (`--token-file`, `--token-stdin`, or `TENDRIL_ENROLL_TOKEN`, avoiding shell history / argv exposure), and optional external trust anchors. Pass `--redact-logs` to `tendril serve` in shared environments so `pairing_code`, decrypted application payload `utf8`, and `token_nonce` are emitted as `"<redacted>"` instead of plaintext on stdout JSON logs:

```bash
# Register an external trust anchor (optional; omit for self-issued host tokens)
tendril --state-dir ./host-state anchor add ci-admin --signing-pub "<b64url_ed25519_pub>"
tendril --state-dir ./host-state anchor list

# Serve with opt-in M2M enrollment and redacted stdout event logs
tendril --state-dir ./host-state serve --listen 127.0.0.1:0 --allow-enroll --redact-logs

# Mint a single-use token (0o600 --out file) and enroll with mandatory host key pinning
tendril --state-dir ./host-state enroll-token --target-host my-host --ttl-secs 900 --out ./token.json
tendril --state-dir ./runner-state enroll \
  --endpoint 127.0.0.1:PORT \
  --host-id my-host \
  --host-static-pub "<b64url_host_static>" \
  --host-signing-pub "<b64url_host_signing>" \
  --token-file ./token.json

# Mint application grants after enrollment (still default deny), revoke unused nonces, or rotate keys
tendril --state-dir ./host-state mint <runner_device_id> --cap fs.read
tendril --state-dir ./host-state revoke-token "<token_nonce>"
tendril --state-dir ./host-state anchor revoke ci-admin
tendril --state-dir ./host-state rotate
```

Once revoked, subsequent `dial` attempts fail closed on the host listener during session establishment, and active `tendril serve` sessions reload `roster.json` updates (under `.roster.lock` advisory locking) to terminate revoked peers immediately across ticks or incoming frames (`0x04 REKEY`, `0x01 DATA`). `tendril rotate` re-signs any persisted self-issued CRL automatically under the new key so revoked tokens stay blocked across key rotation.

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

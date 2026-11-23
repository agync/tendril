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

Launch `tendril-relay` locally or build the rootless container defined in the root `Containerfile`:

```bash
cargo run -p tendril-relay -- --listen 127.0.0.1:8443 --host localhost
```

In production deployments, terminate TLS directly on `tendril-relay` (`--tls-cert` and `--tls-key`, where `--tls-key` enforces `0600` regular non-symlink file permissions, serving `wss://<host>/v1/relay` and `wss://<host>/v2/relay`) or behind a trusted reverse proxy configured with `--trusted-proxy <CIDR>`. Right-to-left header extraction runs only when the TCP peer matches `--trusted-proxy`, using `--trusted-proxy-header <xff|forwarded>` (default `xff`, explicitly selected rather than allowing `Forwarded` to bypass `X-Forwarded-For`). Trusted-proxy peers take a pre-upgrade semaphore permit (`(max_total_connections / 4).max(1)`) and run handshake upgrade under a `min(5s, accept_timeout)` timeout; per-IP `ip_guard` limits apply to the extracted client IP after upgrade. Reverse proxies should strip or overwrite untrusted client forwarding headers. Rate limits normalize IPv4-mapped addresses and group IPv6 addresses by `/64` prefix alongside global `--max-connections` and `--max-mailboxes` caps.

### Managed relay admission (Tiers 1-3 and `--auth-scope`)

Both `/v1/relay` and `/v2/relay` support stateless admission control (`allowlist OR proof`, not additive):

- **Tier 1 (Allowlist):** `--allow-mailbox <b64url_pub>` or `--allow-mailboxes-file <path>` admits listed mailbox keys on `register` and `accept` without an additional HMAC or ticket proof. An empty or comment-only file (`0` valid keys) fails closed at startup.
- **Tier 2 (Shared HMAC):** `--auth-secret-file <path>` (enforces `0600` regular non-symlink file permissions) or `TENDRIL_RELAY_AUTH_SECRET` verifies `tendril-relay-auth-v1\0` HMAC-SHA256 proofs. `tendril-relay` reads `TENDRIL_RELAY_AUTH_SECRET` once at startup rather than stripping the process environment.
- **Tier 3 (`RelayTicket`):** `--issuer-pub <b64url_pub>` verifies JCS-canonical Ed25519 `RelayTicket` proofs (`tendril-relay-ticket-v1\0`, `role: register | dial | any`, `1..=86400s` TTL, `+-30s` skew). Treat a `RelayTicket` as a **bearer credential** when shared over untrusted channels or logs unless scoped to `target_pub` and a short TTL.
- **`--auth-scope <all|register-only>`:** Defaults to `all` whenever any admission mechanism is active (requiring admission on both `register` and `dial`, checking `auth` right after decode before mailbox lookup or epoch skew checks). Passing `--auth-scope` with no allowlist, secret, or issuer fails closed; `--auth-scope register-only` with Tier 1 alone leaves `dial` open because Tier 1 is peer-mailbox allowlisting.

> [!NOTE]
> For container and Kubernetes deployments, mount projected secrets as `0600` regular non-symlink files (for example, by copying or mounting without symlink indirection or group/world read bits): `tendril-relay` enforces `0600` regular non-symlink checks on `--auth-secret-file` and `--tls-key` (and regular non-symlink checks on `--allow-mailboxes-file`), while `tendril` CLI enforces `0600` regular non-symlink checks on `--code-file`, `--token-file`, `--grant @path`, `--relay-auth-secret-file`, `--relay-ticket-file`, `--p2p-relay-token-file`, `--p2p-api-secret-file`, `--wake-secret-file`, and `--wake-auth-header-file`.

```bash
# Mint a Tier 3 RelayTicket using tendril relay-ticket
tendril --state-dir ./issuer-state relay-ticket \
  --relay-host relay.example --role dial --target-pub "<b64url_pub>" --ttl-secs 300
```

## Endpoint lifecycle with `tendril`

Each endpoint isolates its `0o700` state directory containing `0o600` `identity.json` and `roster.json` files:

```bash
# 1. Initialize host and client identities
tendril --state-dir ./host-state init --host-id my-host
tendril --state-dir ./cli-state init

# 2. Start host listener (direct TCP, optional relay/embedded-relay/p2p/overlay/broker, and pairing code)
tendril --state-dir ./host-state serve --listen 127.0.0.1:0 --issue-code lan

# Optional multi-rung host serving (zero-setup P2P, managed relays, Wire v2, or wake hints):
# tendril --state-dir ./host-state serve --p2p --embedded-relay --wire-v2 --issue-code remote
# tendril --state-dir ./host-state serve --p2p-relay https://relay.example/ --p2p-relay-token-file ./p2p.tok --p2p-pkarr --ephemeral-p2p
# tendril --state-dir ./host-state serve --relay wss://relay.example --wire-v2 --relay-v2 --relay-auth-secret-file ./relay.sec
# tendril --state-dir ./host-state serve --p2p-local --overlay 127.0.0.1:0 --overlay-allow-non-tailnet --broker 127.0.0.1:0 --issue-code remote
# (Pass --p2p-local or TENDRIL_P2P_LOCAL=1 on serve/pair/dial for offline local P2P;
#  --overlay rejects non-Tailscale CGNAT/ULA peer IPs by default unless --overlay-allow-non-tailnet is passed;
#  --p2p-relay is repeatable (1..=8 URLs, or default/disabled) and disables n0 Pkarr/DNS by default unless --p2p-pkarr is passed;
#  pass --p2p-relay-token-file (or TENDRIL_P2P_RELAY_TOKEN) for static iroh-relay bearer tokens, or
#  --p2p-api-secret-file (or TENDRIL_P2P_API_SECRET) when built with p2p-iroh-services for RCAN tokens;
#  pass --relay-auth-secret-file (or TENDRIL_RELAY_AUTH_SECRET) or --relay-ticket-file on serve/pair/dial for managed Tendril relays;
#  pass --wire-v2 on serve/pair/dial for Wire 0x02 PAKE/pseudonymous sessions;
#  --relay-v2 requires --wire-v2 AND --relay or --embedded-relay (--relay-host alone errors);
#  pass --wake-url (requires --wire-v2), --wake-adapter <webhook|apns|fcm|unified-push> (default webhook),
#  --wake-secret-file (or TENDRIL_WAKE_SECRET), --wake-auth-header-file, and --wake-pre-wake on dial for opaque wake hints;
#  CLI secret files and --relay-ticket-file enforce regular non-symlink files <= 16 KiB with Unix 0600 permissions (mode & 0o077 == 0);
#  pass --no-pkarr on default relay mode to opt out of Pkarr/DNS, or --include-direct-addrs for non-metadata ?addr= hints.)

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

Autonomous devices enroll without SAS interaction using `serve --allow-enroll`, single-use enrollment tokens (`--token-file`, `--token-stdin`, or `TENDRIL_ENROLL_TOKEN`, avoiding shell history / argv exposure), and optional external trust anchors. Unknown, expired, and already-burned interactive pairing codes normalize computation with a uniform Argon2id dummy verification pass and return `"unauthorized"` on the wire so responders do not oracle-distinguish code validity. Pass `--redact-logs` to `tendril serve` in shared environments so `pairing_code`, decrypted application payload `utf8`, and `token_nonce` are emitted as `"<redacted>"` instead of plaintext on stdout JSON logs:

```bash
# Register an external trust anchor (optional; omit for self-issued host tokens)
tendril --state-dir ./host-state anchor add ci-admin --signing-pub "<b64url_1984b_hybrid_pub>"
tendril --state-dir ./host-state anchor list

# Serve with opt-in M2M enrollment and redacted stdout event logs
tendril --state-dir ./host-state serve --listen 127.0.0.1:0 --allow-enroll --redact-logs

# Mint a single-use token (0o600 --out file) and enroll with mandatory host key pinning
# (--host-signing-pub accepts either the 1984 B b64url key or 32 B signing_pub_hash)
tendril --state-dir ./host-state enroll-token --target-host my-host --ttl-secs 900 --out ./token.json
tendril --state-dir ./runner-state enroll \
  --endpoint 127.0.0.1:PORT \
  --host-id my-host \
  --host-static-pub "<b64url_host_static>" \
  --host-signing-pub "<b64url_host_signing_or_hash>" \
  --token-file ./token.json

# Mint application grants after enrollment (still default deny), revoke unused nonces, or rotate keys
tendril --state-dir ./host-state mint <runner_device_id> --cap fs.read
tendril --state-dir ./host-state revoke-token "<token_nonce>"
tendril --state-dir ./host-state anchor revoke ci-admin
tendril --state-dir ./host-state rotate
```

Once revoked, subsequent `dial` attempts fail closed on the host listener during session establishment, and active `tendril serve` sessions reload `roster.json` updates (under `.roster.lock` advisory locking) to terminate revoked peers immediately across ticks or incoming frames (`0x04 REKEY`, `0x01 DATA`). `tendril rotate` re-signs any persisted self-issued CRL automatically under the new key so revoked tokens stay blocked across key rotation.

## Peer groups

`tendril group` manages a small signed mesh rooted at the local identity. The CLI only builds and persists manifests and drives `GroupPool`; verification and authorization stay in `tendril-core`. Members must already be in the roster as `Active` peers with a known signing key, learned by code pairing or M2M enrollment; peers code-paired before the signing key claim existed fail closed until they re-pair and the operator confirms the new SAS. Group commands require `host_id` to equal `device_id`, and a root identity roots exactly one group because the id derives from its signing key. Endpoint hints may be bare `host:port` (treated as `direct:`) or any other provider hint.

```bash
tendril --state-dir ./a-state group create --name team --endpoint 127.0.0.1:7000
tendril --state-dir ./a-state group add <group_id> --peer <b_device_id> --endpoint 127.0.0.1:7001
tendril --state-dir ./a-state group sync <group_id> --timeout 10
tendril --state-dir ./b-state group broadcast <group_id> --message "hello"
tendril --state-dir ./a-state group remove <group_id> --peer <b_device_id>
tendril --state-dir ./a-state group list
tendril --state-dir ./a-state group show <group_id>
```

- `add` defaults member caps to `group.send:<group_id>` and `group.recv:<group_id>`; repeat `--cap` to override.
- `remove` revokes the member and rotates the rendezvous key. Run `sync` afterwards so reachable members ingest the new manifest and drop the revoked peer.
- `sync` pushes the manifest (and the rendezvous key from the root) and prints `{group_id, seq, delivered, offline, failed}`; `broadcast` prints the `BroadcastReport`. `list` and `show` never print the rendezvous key.
- `sync` and `broadcast` dial siblings over direct, local, relay (`--relay-auth-secret-file` or `--relay-ticket-file`), overlay, and broker endpoints, and over p2p (`iroh://`) when `--p2p` or any other `--p2p-*` option is given; `serve` adds p2p to its group dialers under the same rule as it enables its own p2p listener. `/v2/relay` sibling endpoints are not dialed.
- `tendril serve` ingests pushed `0x0A` and `0x0B` frames from confirmed peers. An unknown group is pinned only when the sender is the manifest signer, an `Active` paired peer whose pinned signing key signed the manifest, and the manifest lists the local device. Once stored groups include the local device, every inbound session passes the pre-auth limiter and is routed after the handshake: a session advertising one local group goes to that group's pool, any other session must come from an `Active` paired peer. Group siblings never enter the roster, so they cannot open ordinary sessions or receive grants without pairing. It prints `group_session_established`, `group_data`, `group_manifest_updated`, `group_member_joined`, `group_member_revoked`, and `group_audit` JSON events.

## JSON stdio conformance peer (`tendril-conformance-peer`)

Cross-language SDK bindings spawn `tendril-conformance-peer` and exchange single-line JSON commands over `stdin`/`stdout` (`stdout` is flushed after every response):

| Command | Purpose |
|---|---|
| `init` | Initialize in-memory or `state_dir`-backed identity and roster |
| `serve_direct`, `serve_relay` | Bind direct TCP or relay WSS listener onto background accept queue |
| `issue_code` | Issue single-use LAN or remote pairing code |
| `add_trust_anchor`, `revoke_trust_anchor` | Manage M2M hybrid signing trust anchors and responder policy |
| `mint_enrollment_token` | Mint single-use M2M enrollment token JSON (enables self-M2M when targeting self) |
| `pair` | Run initiator (`endpoint` + `code`) or responder pairing/M2M exchange |
| `confirm`, `mint`, `revoke` | Transition peer state and mint default-deny signed grants |
| `connect`, `send`, `recv`, `rekey`, `close` | Drive Noise XXhfs session, data exchange, key ratchet, and close |
| `authorize` | Evaluate capability check and return structured `AuditEvent` |
| `shutdown` | Close active listeners/session cleanly and exit |

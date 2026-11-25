# Tendril Stateless WSS Relay Specification v1

Status: **Normative (v1)**

Conventions follow `spec/wire-v1.md`. The relay is an untrusted byte forwarder: it never inspects, decrypts, or logs Tendril plaintext, capability grants, or Noise session payloads.

---

## 1. Endpoint and Transport

- WebSocket endpoint: `wss://<host>/v1/relay` (`ws://<host>/v1/relay` permitted on loopback `127.0.0.1` / `::1` test fixtures).
- Requests to any other HTTP path MUST be rejected before completing the WebSocket upgrade.
- Every forwarded data unit inside binary bridge mode is one WebSocket **binary** frame carrying verbatim Tendril wire bytes (`2 B uint16_be len || body`, total `<= 65521` bytes).
- Relays MUST NOT log application payloads, client device names, pairing codes, or unhashed peer messages.

---

## 2. Challenge-Response Control Protocol

Relay mailbox registration and dial acceptance intentionally use the 32-byte Ed25519 prefix (`relay_pub`) of an endpoint's hybrid signing keypair rather than the full 1984-byte hybrid key. Relays are untrusted byte forwarders with no access to plaintext, grants, or Noise session keys; keeping mailbox challenge-response compact avoids inflating control frames while end-to-end `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` and hybrid `Ed25519 + ML-DSA-65` protect session confidentiality and endpoint identity. Handshake frames (`1216 B` `msg1` and `~4 KiB` `msg2` including `HostHello.signing_pub`) fit within the existing `max_frame = 65521` ceiling.

Upon opening `/v1/relay`, the server sends one JSON text frame (`challenge`) binding the connection to the relay's canonical `host` identity and a fresh 32-byte random `nonce`:

```jsonc
// Server -> Client (initial frame on every /v1/relay connection)
{
  "op": "challenge",
  "nonce": string,        // b64url 32-byte CSPRNG challenge nonce
  "host": string,         // canonical relay host name bound into signatures
  "max_frame": 65521,     // maximum allowed binary frame byte length
  "auth_required"?: string[], // optional: ["register"] or ["register", "dial"]; omitted when open
  "fast_open"?: bool,     // optional: true when relay supports Dial.init_frame (0-RTT)
  "standby"?: bool        // optional: true when relay supports standby acceptor sockets
}
```

### 2.1 Mailbox Registration (Listener Control Socket)

A listening peer registers its 32-byte Ed25519 signing public key as a mailbox address by sending one JSON text frame (`register`):

```jsonc
// Listener -> Server
{
  "op": "register",
  "pub": string,          // b64url 32-byte Ed25519 signing public key
  "sig": string,          // b64url 64-byte strict Ed25519 signature
  "auth"?: RelayAuthProof, // optional stateless admission proof (required when challenge advertises "register")
  "fast_open"?: bool      // optional: true when listener handles Incoming.init_frame
}
```

Signature input (`53 + len(host_utf8)` bytes):

```text
domain_prefix (21 B) = ASCII "tendril-relay-reg-v1\0"
host_utf8     (var)  = UTF-8(challenge.host)
nonce         (32 B) = raw 32-byte decoded challenge.nonce
```

On valid signature verification, the relay binds `pub` to that control WebSocket and replies:

```jsonc
{ "op": "registered", "pub": string }
```

### 2.1.1 Standby Acceptor Sockets (`standby`)

When `challenge.standby == true`, a registered listener MAY park up to `max_standby_per_mailbox = 4` pre-authenticated standby WebSocket connections so incoming dials bridge without a post-dial `accept` round-trip. On each standby connection, the listener verifies `challenge`, signs the identical Section 2.1 `register` input under `pub`, attaches `auth` covering `"register"` when admission requires it, and sends:

```jsonc
// Standby Acceptor -> Server
{
  "op": "standby",
  "pub": string,          // b64url 32-byte Ed25519 mailbox public key (MUST match an active registration)
  "sig": string,          // b64url 64-byte strict Ed25519 signature over Section 2.1 input
  "auth"?: RelayAuthProof // optional stateless admission proof (required when admission covers "register")
}
```

If `pub` is not actively registered, the relay fails closed (`"offline"` or `"unauthorized"`). If `max_standby_per_mailbox` sockets are already parked for `pub`, the relay returns `{ "op": "error", "code": "rate_limited" }` and closes the extra socket. Otherwise it parks the standby socket and replies:

```jsonc
{ "op": "standby_ready" }
```

Parked standby sockets are bound to the primary mailbox registration and close when the primary control socket unregisters or disconnects.

### 2.2 Dial Request, 0-RTT `init_frame`, and Pending Notification

A dialing peer initiates a stream toward a target mailbox key:

```jsonc
// Dialer -> Server
{
  "op": "dial",
  "target_pub": string,   // b64url 32-byte Ed25519 mailbox key
  "conn_id": string,      // b64url 16-byte unique stream identifier
  "auth"?: RelayAuthProof, // optional stateless admission proof (required when challenge advertises "dial")
  "init_frame"?: string   // optional: b64url 1..=65521 raw initial Tendril bytes (only when challenge.fast_open == true)
}
```

When admission covers `dial`, the relay MUST verify `dial.auth` before decoding `init_frame` or looking up `target_pub` so unauthenticated callers cannot probe mailbox presence. If `init_frame` is present, invalid base64url or empty decoded bytes MUST fail with `"bad_request"`, and decoded length exceeding `max_frame` (`65521` bytes) MUST fail with `"frame_too_large"`. Relay control frames permit up to `131072` bytes (`128 KiB`) of JSON text so a base64url-encoded `65521`-byte `init_frame` fits while binary forwarding remains capped at `65521` bytes.

If `target_pub` has an active control connection and `active_count` / `pending_count` are below cap:

1. **Standby hit:** If a live standby socket is parked for `target_pub` (skipping any dead standby socket found at dequeue), the relay pops it atomically, sends `{ "op": "incoming", "conn_id": string }` (adding `"init_frame"` when the listener registered `"fast_open": true`) on that standby socket, sends `{ "op": "ready", "conn_id": string }` to the dialer, and enters binary bridge mode immediately on both sockets without an `accept` round-trip. If the dialer supplied `init_frame` but the listener did not register `"fast_open": true`, the relay injects the decoded bytes as the first WebSocket binary frame toward the acceptor immediately after stream transition.
2. **Classic fallback:** When no live standby socket is parked, the relay holds the dial pending, pushes `incoming` on the primary control WebSocket (carrying `"init_frame"` only when the listener registered `"fast_open": true`), and waits for `accept`. If that control connection ends before the dial is accepted, the relay MUST fail the dial with `"offline"` at once rather than hold it until `accept_timeout`:

```jsonc
// Server -> Listener (control socket or consumed standby socket)
{
  "op": "incoming",
  "conn_id": string,
  "init_frame"?: string   // present when dialer sent init_frame and listener registered fast_open=true
}
```

A valid `accept` (Section 2.3) claims the pending dial atomically, and the claim and the dial's own withdrawal are mutually exclusive. If the control connection ends or `accept_timeout` passes after an `accept` claimed the dial, the claim wins: the relay MUST NOT fail the dial with `"offline"` or `"timeout"` and answers both sockets with `ready`, failing the dial with `"offline"` only if the relay cannot deliver `ready` to the acceptor socket. If the dial is withdrawn first, it fails with `"offline"` or `"timeout"` and a later `accept` for its `conn_id` fails with `"invalid_request"`.

### 2.3 Anti-Hijack Stream Accept (Listener Data Socket)

To claim a pending `conn_id` delivered via classic `incoming`, the listener opens a fresh `/v1/relay` WebSocket connection, receives a new `challenge` (`nonce_accept`), and sends:

```jsonc
// Listener data socket -> Server
{
  "op": "accept",
  "pub": string,          // b64url 32-byte Ed25519 mailbox key (MUST match dial.target_pub)
  "conn_id": string,      // b64url 16-byte pending stream identifier
  "sig": string,          // b64url 64-byte strict Ed25519 signature
  "auth"?: RelayAuthProof // optional stateless admission proof (required when admission covers "register")
}
```

Signature input (`72 + len(host_utf8)` bytes):

```text
domain_prefix (24 B) = ASCII "tendril-relay-accept-v1\0"
host_utf8     (var)  = UTF-8(challenge.host)
nonce_accept  (32 B) = raw 32-byte decoded challenge.nonce of the accept socket
conn_id       (16 B) = raw 16-byte decoded conn_id
```

On valid signature and `accept.pub == pending.target_pub`, the relay sends `ready` to BOTH the dialer socket and the acceptor socket, then enters raw binary forwarding mode (if the dialer supplied `init_frame` while the listener did not register `"fast_open": true`, the relay injects the decoded `init_frame` bytes as the first WebSocket binary frame sent to the acceptor after `ready`):

```jsonc
{ "op": "ready", "conn_id": string }
```

Requiring strict Ed25519 proof on `register`, `standby`, and `accept` bound to the connection's `nonce` and `host` prevents mailbox hijacking, cross-relay signature replay, and third-party theft of pending incoming dials.

### 2.4 Error Frames

Before entering binary forwarding mode, control errors return one JSON text frame and close the WebSocket:

```jsonc
{ "op": "error", "code": string }
```

Standard error `code` values: `"unauthorized"`, `"offline"`, `"rate_limited"`, `"capacity_exceeded"`, `"invalid_request"`, `"bad_request"`, `"frame_too_large"`, `"timeout"`.

### 2.5 Stateless Admission Tiers 1-3 and Option 1A Scoping

Relays MAY enforce admission control without maintaining user accounts or per-session databases across three composable tiers:

1. **Tier 1 (Static Mailbox Allowlist):** The relay holds an explicit set of permitted 32-byte Ed25519 mailbox keys (`pub`) for `register` (and `accept`). Tier 1 allowlisted keys (`--allow-mailbox` / `--allow-mailboxes-file`) are an **alternative** to Tier 2/3 proofs (`allowlist OR proof`, not additive): allowlisted identities are admitted on `register` and `accept` without requiring an additional HMAC or `RelayTicket` proof.
2. **Tier 2 (Shared HMAC Secret):** Clients present `auth` with `"kind": "hmac"` proven under a shared secret (`1..=4096` bytes, `MAX_RELAY_AUTH_SECRET_BYTES = 4096`):
   ```jsonc
   { "kind": "hmac", "mac": string } // b64url 32-byte HMAC-SHA256
   ```
   HMAC-SHA256 input (`87 + len(op) + len(canonical_host)` bytes):
   ```text
   domain_prefix (22 B) = ASCII "tendril-relay-auth-v1\0"
   op            (var)  = ASCII "register" | "dial" | "accept"
   separator     ( 1 B) = 0x00
   host_utf8     (var)  = UTF-8(canonical(challenge.host))
   nonce         (32 B) = raw 32-byte decoded challenge.nonce
   pub_or_target (32 B) = raw 32-byte pub (register/accept) or target_pub (dial)
   ```
   Relays MUST verify `mac` in constant time (`subtle::ConstantTimeEq`).
3. **Tier 3 (Stateless Ed25519 Signed `RelayTicket`):** Clients present `auth` with `"kind": "ticket"` carrying a JCS-canonical Ed25519 capability ticket signed by a key in the relay's `trusted_issuers` list:
   ```jsonc
   {
     "kind": "ticket",
     "ticket": {
       "v": 1,
       "issuer_pub": string,  // b64url 32-byte Ed25519 issuer key
       "relay_host": string,  // canonical relay host
       "role": "register" | "dial" | "any",
       "target_pub": string,  // "*" or b64url 32-byte Ed25519 key
       "not_before": uint64,  // Unix seconds
       "not_after": uint64,   // Unix seconds
       "sig": string          // b64url 64-byte strict Ed25519 signature
     }
   }
   ```
   Signed byte input:
   ```text
   "tendril-relay-ticket-v1\0" (24 B) || RFC8785_JCS(ticket without "sig")
   ```
   Ticket verification MUST enforce all of:
   - `v == 1`, `not_before < not_after`, and `not_after - not_before <= 86400` (`1..=86400 s` TTL).
   - Clock check with `+-30 s` skew tolerance: `now_unix + 30 >= not_before` and `now_unix <= not_after + 30`.
   - `canonical(ticket.relay_host) == canonical(relay_expected_host)` via `canonical_relay_host` (lowercase ASCII, trailing dot stripped, no `:port`, path, userinfo, or control chars).
   - Role matching: `register` and `accept` require `role in {"register", "any"}`; `dial` requires `role in {"dial", "any"}`.
   - Target binding: `ticket.target_pub == "*"` OR decoded 32-byte key equals `pub` (`register`/`accept`) or `target_pub` (`dial`) in constant time (a `dial` ticket with a concrete key authorizes ONLY that target key).
   - Issuer trust: `trusted_issuers` MUST be non-empty and contain decoded `issuer_pub` (constant-time match), verified with strict Ed25519 (`verify_strict`).
   - Unknown JSON fields inside `auth` or `ticket` MUST be rejected (`deny_unknown_fields`).

**Option 1A Admission Scoping (`auth_scope`):**

- `auth_scope = "all"` (default whenever a shared HMAC secret or trusted ticket issuers are configured): requires valid admission proof on `register`, `accept`, AND `dial`. `challenge.auth_required` MUST be `["register", "dial"]`.
- `auth_scope = "register-only"` (default when ONLY a Tier 1 mailbox allowlist is configured, or explicitly configured for Tier 2/3 when open dialing is desired): requires admission on `register` (and `accept` when Tier 2/3 is active); `dial` does not require `auth`. `challenge.auth_required` MUST be `["register"]`.
- When no admission controls are configured (open relay), `auth_required` is omitted from `challenge`.
- **Zero Mailbox Presence Leak on `dial`:** Whenever `auth_scope` covers `dial` (`"all"`), the relay MUST validate `dial.auth` right after frame decode, BEFORE mailbox lookup (`target_pub` in the active mailbox table) or epoch skew checks. Any missing or invalid proof MUST fail closed immediately with `{ "op": "error", "code": "unauthorized" }` so unauthenticated callers cannot probe whether a mailbox is currently online (`"offline"` vs `"unauthorized"`).

---

## 3. Binary Bridge and Abuse Bounds

Once `ready` has been sent:

- Only WebSocket binary frames (`opcode = 0x2`) and WebSocket close/control frames are valid; any text frame closes both sides.
- Any binary frame exceeding `65521` bytes (`2 B` outer frame length + `65519 B` max Noise body) MUST be rejected before forwarding and close both sockets.
- Relay implementations MUST enforce bounded abuse limits:

| Limit | Default v1 Value | Enforcement |
|---|---|---|
| `max_frame` | `65521` bytes | Close both halves immediately on oversize frame |
| `max_tracked_ips` | `4096` entries | LRU-bounded per-IP/prefix (`/64` IPv6) token bucket table with eviction-overflow throttling |
| `max_total_connections` | `4096` active sockets | Reject above cap immediately at accept |
| `max_mailboxes` | `1024` registered keys | Return `"capacity_exceeded"` on new registrations above cap |
| `max_standby_per_mailbox` | `4` standby sockets | Return `"rate_limited"` above cap |
| `max_pending_per_mailbox` | `8` concurrent pending dials | Return `"rate_limited"` above cap |
| `max_active_per_ip` | `64` active connections | Reject above cap before holding state |
| `max_active_per_mailbox` | `64` active bridged streams | Reject above cap |
| `accept_timeout` | `15 s` | Fail pending dial with `"timeout"` if unaccepted |
| `idle_timeout` | `300 s` | Close idle streams without activity |
| `write_timeout` | `1 s` | Terminate slow-reader sink without unbounded buffering |

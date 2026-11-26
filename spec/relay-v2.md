# Tendril Stateless WSS Relay Specification v2

Status: **Normative (v2)**

Conventions follow `spec/wire-v2.md`. The relay is an untrusted byte forwarder: it never inspects, decrypts, or logs Tendril plaintext, capability grants, Noise payloads, or endpoint static identities.

---

## 1. Endpoint and Transport

- WebSocket endpoint: `wss://<host>/v2/relay` (`ws://<host>/v2/relay` permitted on loopback `127.0.0.1` / `::1` test fixtures).
- Relays MAY answer unauthenticated plain HTTP `GET /healthz` and `HEAD /healthz` liveness probes (carrying no `Upgrade` or `Sec-WebSocket-Key` header) with `200 OK` (`Content-Type: text/plain; charset=utf-8`, `Cache-Control: no-store`, body `ok` on `GET`).
- WebSocket upgrade requests targeting `/healthz` and requests to any other HTTP path MUST be rejected before completing the WebSocket upgrade (note that `/v1/relay` remains served independently per `spec/relay-v1.md` for legacy peers).
- Every forwarded data unit inside binary bridge mode is one WebSocket **binary** frame carrying verbatim Tendril wire bytes (`2 B uint16_be len || body`, total `<= 65521` bytes).
- Relays MUST NOT log application payloads, client device names, pairing codes, unhashed peer messages, or long-term device identifiers.

---

## 2. Blinded Epoch Mailbox Cryptography

In `/v1/relay`, listeners register under their persistent 32-byte Ed25519 `relay_pub`, allowing an honest-but-curious relay operator to correlate a device across sessions, IP changes, and time. `/v2/relay` eliminates long-term relay mailbox identifiers by rotating unlinkable per-epoch Ed25519 mailbox addresses derived from a shared 32-byte `mailbox_secret`.

### 2.1 Epoch Definition and Transition Window

- Epoch duration: `3600` seconds (1 hour).
- Epoch index for Unix timestamp `unix_secs`: `epoch = unix_secs / 3600`.
- To tolerate clock skew across hour boundaries, peers MAY derive a sliding window `(epoch - 1, epoch, epoch + 1)` and check `|epoch - server_epoch| <= 1`. See Section 4.1 for connection isolation requirements to preserve cross-epoch unlinkability.

### 2.2 Per-Epoch Key Derivation

Given the shared 32-byte `mailbox_secret` (exported from a completed v2 handshake per `spec/wire-v2.md` Section 3.1.1) and big-endian `epoch_be = uint64_be(epoch)`:

```text
epoch_seed    = HKDF-SHA256(
    ikm  = mailbox_secret,
    salt = epoch_be (8 B),
    info = "tendril-relay-v2-ed25519"
)

dial_auth_key = HKDF-SHA256(
    ikm  = mailbox_secret,
    salt = epoch_be (8 B),
    info = "tendril-relay-v2-dial-auth"
)

(mailbox_sk, mailbox_id) = Ed25519_Keypair_From_Seed(epoch_seed)
```

- `mailbox_id` (`32` bytes, `b64url` on JSON control frames) IS the ephemeral mailbox address for `epoch`.
- Because `epoch_seed` and `dial_auth_key` use distinct HKDF `info` labels and per-epoch salts, `mailbox_id(E)` and `mailbox_id(E + 1)` are computationally unlinkable to any party lacking `mailbox_secret`.

---

## 3. Challenge-Response Control Protocol

Upon opening `/v2/relay`, the server sends one JSON text frame (`challenge`) binding the connection to the relay's canonical `host` identity, current server `epoch`, and a fresh 32-byte CSPRNG `nonce`:

```jsonc
// Server -> Client (initial frame on every /v2/relay connection)
{
  "op": "challenge",
  "nonce": string,        // b64url 32-byte CSPRNG challenge nonce
  "host": string,         // canonical relay host name bound into proofs
  "epoch": uint64,        // current relay server epoch (unix_secs / 3600)
  "max_frame": 65521,     // maximum allowed binary frame byte length
  "auth_required"?: string[], // optional: ["register"] or ["register", "dial"]; omitted when open
  "fast_open"?: bool,     // optional: true when relay supports Dial.init_frame (0-RTT)
  "standby"?: bool        // optional: true when relay supports standby acceptor sockets
}
```

- Clients MUST canonicalize `challenge.host` (ASCII lowercase, trailing dot stripped, no `:port`, path, userinfo, or control chars; note `canonical(host)` excludes `:port` and represents the hostname only) and MUST verify `canonical(challenge.host) == canonical(dialed_url_host)` (`VerifiedRelayHost`) BEFORE signing any `register`, `standby`, `dial`, or `accept` proof, preventing cross-relay challenge forwarding attacks.

### 3.1 Blinded Mailbox Registration (Listener Control Socket)

A listening peer registers an ephemeral `mailbox_id` for `epoch` by sending one JSON text frame (`register`):

```jsonc
// Listener -> Server
{
  "op": "register",
  "mailbox_id": string,   // b64url 32-byte per-epoch Ed25519 public key
  "epoch": uint64,        // epoch index covered by this mailbox_id
  "sig": string,          // b64url 64-byte strict Ed25519 signature under mailbox_sk
  "auth"?: RelayAuthProof, // optional stateless admission proof (required when challenge advertises "register")
  "fast_open"?: bool      // optional: true when listener handles Incoming.init_frame
}
```

Signature input (`61 + len(host_utf8)` bytes):

```text
domain_prefix (21 B) = ASCII "tendril-relay-reg-v2\0"
host_utf8     (var)  = UTF-8(canonical(challenge.host))
nonce         (32 B) = raw 32-byte decoded challenge.nonce
epoch_be      ( 8 B) = big-endian uint64(epoch)
```

- Relays MUST validate `mailbox_id` as a non-weak Ed25519 verifying key, enforce `|epoch - server_epoch| <= 1`, and verify `sig` with strict Ed25519 verification.
- On success, the relay binds `mailbox_id` to that control WebSocket and replies:

```jsonc
{ "op": "registered", "mailbox_id": string, "epoch": uint64 }
```

### 3.1.1 Standby Acceptor Sockets (`standby`)

When `challenge.standby == true`, a registered listener MAY park up to `max_standby_per_mailbox = 4` pre-authenticated standby WebSocket connections per `(mailbox_id, epoch)`. Each standby socket connects independently (never chaining multiple epochs on one socket per Section 4.1), verifies `challenge`, signs the exact Section 3.1 `register` input under `mailbox_sk`, attaches `auth` covering `"register"` when admission requires it, and sends:

```jsonc
// Standby Acceptor -> Server
{
  "op": "standby",
  "mailbox_id": string,   // b64url 32-byte per-epoch Ed25519 public key (MUST match active registration)
  "epoch": uint64,        // epoch index matching the active registration
  "sig": string,          // b64url 64-byte strict Ed25519 signature over Section 3.1 input
  "auth"?: RelayAuthProof // optional stateless admission proof (required when admission covers "register")
}
```

If `(mailbox_id, epoch)` is not actively registered or its registered epoch differs, the relay fails closed (`"offline"` or `"unauthorized"`). If `max_standby_per_mailbox` sockets are already parked for `mailbox_id`, the relay returns `{ "op": "error", "code": "rate_limited" }` and closes the socket. Otherwise it parks the standby socket and replies:

```jsonc
{ "op": "standby_ready", "mailbox_id": string, "epoch": uint64 }
```

Parked standby sockets are bound to that `(mailbox_id, epoch)` primary control connection and close when it unregisters, disconnects, or rotates out of the active epoch window.

### 3.2 Authenticated Dial Request, 0-RTT `init_frame`, and Pending Notification

A dialing peer initiates a stream toward an active epoch `target_mailbox_id` with a fresh 16-byte `conn_id` by computing a `dial_token` using `dial_auth_key`:

```text
dial_mac_input = "tendril-relay-v2-dial\0" (22 B)
              || host_utf8 (var)
              || challenge_nonce (32 B)
              || target_mailbox_id (32 B)
              || conn_id (16 B)
              || epoch_be (8 B)

dial_token = HMAC-SHA256(key = dial_auth_key, msg = dial_mac_input)
```

The dialer sends:

```jsonc
// Dialer -> Server
{
  "op": "dial",
  "target_mailbox_id": string,  // b64url 32-byte epoch Ed25519 mailbox key
  "epoch": uint64,              // epoch index used to derive target_mailbox_id
  "conn_id": string,            // b64url 16-byte unique stream identifier
  "dial_token": string,         // b64url 32-byte HMAC-SHA256 capability proof
  "auth"?: RelayAuthProof,      // optional stateless admission proof (required when challenge advertises "dial")
  "init_frame"?: string         // optional: b64url 1..=65521 raw initial Tendril bytes (only when challenge.fast_open == true)
}
```

When admission covers `dial`, the relay MUST validate `dial.auth` first, then validate `init_frame` (`"bad_request"` on invalid base64url or empty decoded payload; `"frame_too_large"` when decoded length exceeds `65521` bytes), then check epoch skew (`|epoch - server_epoch| <= 1`), before looking up `target_mailbox_id` (zero mailbox presence leak). Relay control frames permit up to `131072` bytes (`128 KiB`) of JSON text while binary forwarding remains capped at `65521` bytes.

If `target_mailbox_id` has an active control connection for `epoch` and `active_count` / `pending_count` are below cap:

1. **Standby hit:** If a live standby socket is parked for `target_mailbox_id` (skipping any dead standby socket found at dequeue), the relay pops it atomically, sends `incoming` (with `"init_frame"` if the listener registered `"fast_open": true`) directly on that standby socket, sends `{ "op": "ready", "conn_id": string }` to the dialer, and enters binary bridge mode immediately on both sockets. If the dialer supplied `init_frame` while the listener did not register `"fast_open": true`, the relay injects the decoded bytes as the first WebSocket binary frame toward the standby socket immediately after stream transition.
2. **Classic fallback:** If no live standby socket is parked, the relay pushes `incoming` on the control WebSocket (including `"init_frame"` only when `"fast_open": true` was registered) and holds the dial waiting for `accept`. If that registration ends before the dial is accepted, the relay MUST fail the dial with `"offline"` at once rather than hold it until `accept_timeout`. A registration ends when its control connection closes, when its epoch rotates out of the window, when a later `register` for the same `mailbox_id` replaces it (Section 3.4), or when its admission ticket expires (Section 3.5):

```jsonc
// Server -> Listener (control socket or consumed standby socket)
{
  "op": "incoming",
  "mailbox_id": string,
  "epoch": uint64,
  "conn_id": string,
  "dial_nonce": string,         // b64url 32-byte challenge nonce from dialer's connection
  "dial_token": string,         // b64url 32-byte HMAC-SHA256 dial proof
  "init_frame"?: string         // present when dialer sent init_frame and listener registered fast_open=true
}
```

- Before emitting an accepted stream (either from a consumed standby socket or before opening an `accept` data socket in classic mode), the listener MUST validate and record the notification atomically (e.g. via `verify_and_record_v2_relay_dial`):
  1. Look up `epoch` in its active `RelayEpochWindow` (`epoch >= min_valid_epoch`) and verify `dial_token` against `dial_auth_key` over `("tendril-relay-v2-dial\0" || canonical(relay_host) || dial_nonce || mailbox_id || conn_id || epoch_be)` using constant-time comparison (`subtle::ConstantTimeEq`).
  2. ONLY AFTER `dial_token` verifies, check and record `(epoch, dial_nonce, conn_id)` in a bounded `RelayDialReplayCache` to reject replayed `incoming` notifications from a malicious relay. At capacity, `RelayDialReplayCache` evicts only expired epochs (`epoch < min_valid_epoch`) and fails closed without evicting live entries.
- If `dial_token` fails verification, is replayed, or `epoch` is outside the listener's active window: on classic control sockets, the listener MUST silently ignore the `incoming` notification without opening a data connection; on a consumed standby socket, the listener MUST close that standby socket before acquiring an accept permit or handing any bytes to the upper session driver.

A valid `accept` (Section 3.3) claims the pending dial atomically, and the claim and the dial's own withdrawal are mutually exclusive. If the control connection ends or `accept_timeout` passes after an `accept` claimed the dial, the claim wins: the relay MUST NOT fail the dial with `"offline"` or `"timeout"` and answers both sockets with `ready`, failing the dial with `"offline"` only if the relay cannot deliver `ready` to the acceptor socket. If the dial is withdrawn first, it fails with `"offline"` or `"timeout"` and a later `accept` for its `conn_id` fails with `"invalid_request"`.

### 3.3 Anti-Hijack Stream Accept (Listener Data Socket)

To claim a verified pending `conn_id` in classic mode, the listener opens a fresh `/v2/relay` WebSocket connection, receives a new `challenge` (`nonce_accept`), verifies `canonical(challenge.host) == canonical(dialed_url_host)`, and sends:

```jsonc
// Listener data socket -> Server
{
  "op": "accept",
  "mailbox_id": string,   // b64url 32-byte epoch mailbox key (MUST match dial.target_mailbox_id)
  "epoch": uint64,        // epoch index (MUST match dial.epoch)
  "conn_id": string,      // b64url 16-byte pending stream identifier
  "sig": string,          // b64url 64-byte strict Ed25519 signature under mailbox_sk
  "auth"?: RelayAuthProof // optional stateless admission proof (required when admission covers "register")
}
```

Signature input (`80 + len(host_utf8)` bytes):

```text
domain_prefix (24 B) = ASCII "tendril-relay-accept-v2\0"
host_utf8     (var)  = UTF-8(canonical(challenge.host))
nonce_accept  (32 B) = raw 32-byte decoded challenge.nonce of the accept socket
conn_id       (16 B) = raw 16-byte decoded conn_id
epoch_be      ( 8 B) = big-endian uint64(epoch)
```

On valid strict Ed25519 verification and `accept.mailbox_id == pending.target_mailbox_id`, the relay sends `ready` to BOTH the dialer socket and the acceptor socket, then enters raw binary forwarding mode (injecting decoded `init_frame` bytes as the first WebSocket binary frame toward the acceptor if the dialer supplied `init_frame` while the listener omitted `"fast_open": true`):

```jsonc
{ "op": "ready", "conn_id": string }
```

### 3.4 Error Frames

Control errors prior to binary bridge mode return one JSON text frame and close the WebSocket:

```jsonc
{ "op": "error", "code": string }
```

Standard error `code` values: `"unauthorized"`, `"offline"`, `"rate_limited"`, `"capacity_exceeded"`, `"invalid_request"`, `"bad_request"`, `"frame_too_large"`, `"timeout"`, `"replaced"`.

Registration of a `mailbox_id` is last writer wins with the same effects as `spec/relay-v1.md` Section 2.4: the earlier registration's pending dials fail with `"offline"`, its parked standby sockets close, and its control socket receives `{ "op": "error", "code": "replaced" }` before it closes.

### 3.5 Stateless Admission Tiers 1-3 and Option 1A Scoping on `/v2/relay`

`/v2/relay` uses the same `RelayAuthProof` (`hmac` and `ticket`), canonical `relay_host` verification, strict `RelayTicket` bounds (`v = 1`, `1..=86400 s` TTL, `+-30 s` skew, RFC 8785 JCS `"tendril-relay-ticket-v1\0"`), and Option 1A `auth_scope` rules defined in `spec/relay-v1.md` Section 2.5, with the following `/v2/relay` bindings:

- **Bound 32-byte key (`pub_or_target` / concrete `target_pub`):**
  - On `register` (`op = "register"`, ticket `required_op = "register"`): binds to the 32-byte decoded `mailbox_id`.
  - On `dial` (`op = "dial"`, ticket `required_op = "dial"`): binds to the 32-byte decoded `target_mailbox_id`.
  - On `accept` (`op = "accept"`, ticket `required_op = "register"`): binds to the 32-byte decoded `mailbox_id`.
- **Epoch unlinkability with Tiers 1-3:**
  - Tier 1 static mailbox allowlists match concrete epoch `mailbox_id` keys and therefore only apply when explicitly configured per epoch (default `auth_scope = "register-only"` when only an allowlist is configured).
  - Tier 2 (shared HMAC secret, `1..=4096` bytes) and Tier 3 (Ed25519 `RelayTicket` with `target_pub = "*"` or epoch `mailbox_id`) operate statelessly without per-epoch relay configuration or long-term client identity disclosure. Both default to Option 1A `auth_scope = "all"` (`challenge.auth_required = ["register", "dial"]`).
  - **Tier 3 wildcard tickets are cross-epoch linkable.** A `RelayTicket` with `target_pub = "*"` is a bearer credential presented verbatim for every mailbox it is used on, so a relay can link all epochs and mailboxes that present the same ticket for its whole TTL (up to `86400` s, i.e. up to 25 epochs). Deployments that require cross-epoch unlinkability MUST NOT use wildcard Tier 3 tickets across epoch boundaries. They MUST use either Tier 2 HMAC, whose proof is bound to the per-epoch `mailbox_id` and a fresh challenge nonce, or per-epoch Tier 3 tickets whose `target_pub` is a concrete epoch `mailbox_id` and whose validity does not leave that epoch (`mint_v2_epoch_relay_ticket` clamps `not_after` below the epoch boundary; `RelayTicket::spans_multiple_v2_epochs` reports whether a ticket crosses one).
- **Ticket lifetime:** A registration or standby socket admitted by a ticket ends at the earlier of its epoch rotation and the ticket deadline of `spec/relay-v1.md` Section 2.5 (`not_after + 30`). Streams bridged before that point run until they close.
- **Zero Mailbox Presence Leak on `dial`:** When `auth_scope` covers `dial` (`"all"`), the relay MUST verify `dial.auth` BEFORE checking whether `target_mailbox_id` is registered or online. Missing or invalid `dial.auth` MUST return `{ "op": "error", "code": "unauthorized" }` and close the socket without revealing mailbox presence.

---

## 4. Binary Bridge, Abuse Bounds, and Privacy Guarantees

Once `ready` has been sent, binary forwarding and abuse limits (`max_frame = 65521`, `max_tracked_ips = 4096`, `max_total_connections = 4096`, `max_mailboxes = 1024`, `max_standby_per_mailbox = 4`, `max_pending_per_mailbox = 8`, `max_active_per_ip = 64`, `max_active_per_mailbox = 64`, `accept_timeout = 15 s`, `idle_timeout = 300 s`, `write_timeout = 1 s`) match `spec/relay-v1.md` Section 3.

### 4.1 Privacy Properties and Epoch Connection Isolation

- **Unlinkability across epochs:** The relay only observes random per-epoch Ed25519 public keys `mailbox_id`. Without `mailbox_secret`, it cannot link `mailbox_id(E)` to `mailbox_id(E + 1)`. This holds for Tier 1, Tier 2, and per-epoch concrete-`mailbox_id` Tier 3 tickets only; a wildcard Tier 3 ticket reused across epochs reintroduces linkability for its TTL (Section 3.5).
- **Single-socket chaining warning:** Registering multiple epoch `mailbox_id` values `(epoch - 1, epoch, epoch + 1)` on a single persistent WebSocket control connection allows the relay to link consecutive epochs via that shared socket. Clients requiring cross-epoch unlinkability MUST open a separate control WebSocket per epoch `mailbox_id`. Listeners MAY maintain separate independent sockets for `(epoch - 1, epoch, epoch + 1)` continuously or register `epoch + 1` on a fresh socket within a brief skew margin before the hour boundary; simultaneous window registration trades boundary-jitter complexity for coarse socket-arrival timing correlation while keeping `mailbox_id` keys cryptographically unlinkable across separate sockets. Note also that network-layer IP correlation remains outside the relay mailbox layer unless routed over an anonymous transport.
- **No online enumeration:** An unauthenticated party lacking `mailbox_secret` cannot predict `mailbox_id` or forge a valid `dial_token` for any host.
- **No trusted relay:** End-to-end `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` with v2 pseudonymous reconnect and bucketed inner padding ensures the relay observes neither identity metadata nor plaintext message lengths.

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

Upon opening `/v1/relay`, the server sends one JSON text frame (`challenge`) binding the connection to the relay's canonical `host` identity and a fresh 32-byte random `nonce`:

```jsonc
// Server -> Client (initial frame on every /v1/relay connection)
{
  "op": "challenge",
  "nonce": string,        // b64url 32-byte CSPRNG challenge nonce
  "host": string,         // canonical relay host name bound into signatures
  "max_frame": 65521      // maximum allowed binary frame byte length
}
```

### 2.1 Mailbox Registration (Listener Control Socket)

A listening peer registers its 32-byte Ed25519 signing public key as a mailbox address by sending one JSON text frame (`register`):

```jsonc
// Listener -> Server
{
  "op": "register",
  "pub": string,          // b64url 32-byte Ed25519 signing public key
  "sig": string           // b64url 64-byte strict Ed25519 signature
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

### 2.2 Dial Request and Pending Notification

A dialing peer initiates a stream toward a target mailbox key:

```jsonc
// Dialer -> Server
{
  "op": "dial",
  "target_pub": string,   // b64url 32-byte Ed25519 mailbox key
  "conn_id": string       // b64url 16-byte unique stream identifier
}
```

If `target_pub` has an active control connection and fewer than `max_pending_per_mailbox` pending dials, the relay pushes an `incoming` notification over the listener's control WebSocket and holds the dialer socket waiting for an `accept`:

```jsonc
// Server -> Listener (control socket)
{
  "op": "incoming",
  "conn_id": string
}
```

### 2.3 Anti-Hijack Stream Accept (Listener Data Socket)

To claim a pending `conn_id`, the listener opens a fresh `/v1/relay` WebSocket connection, receives a new `challenge` (`nonce_accept`), and sends:

```jsonc
// Listener data socket -> Server
{
  "op": "accept",
  "pub": string,          // b64url 32-byte Ed25519 mailbox key (MUST match dial.target_pub)
  "conn_id": string,      // b64url 16-byte pending stream identifier
  "sig": string           // b64url 64-byte strict Ed25519 signature
}
```

Signature input (`72 + len(host_utf8)` bytes):

```text
domain_prefix (24 B) = ASCII "tendril-relay-accept-v1\0"
host_utf8     (var)  = UTF-8(challenge.host)
nonce_accept  (32 B) = raw 32-byte decoded challenge.nonce of the accept socket
conn_id       (16 B) = raw 16-byte decoded conn_id
```

On valid signature and `accept.pub == pending.target_pub`, the relay sends `ready` to BOTH the dialer socket and the acceptor socket, then enters raw binary forwarding mode:

```jsonc
{ "op": "ready", "conn_id": string }
```

Requiring strict Ed25519 proof on BOTH `register` and `accept` bound to the connection's `nonce` and `host` prevents mailbox hijacking, cross-relay signature replay, and third-party theft of pending incoming dials.

### 2.4 Error Frames

Before entering binary forwarding mode, control errors return one JSON text frame and close the WebSocket:

```jsonc
{ "op": "error", "code": string }
```

Standard error `code` values: `"unauthorized"`, `"offline"`, `"rate_limited"`, `"capacity_exceeded"`, `"invalid_request"`, `"timeout"`.

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
| `max_pending_per_mailbox` | `8` concurrent pending dials | Return `"rate_limited"` above cap |
| `max_active_per_ip` | `64` active connections | Reject above cap before holding state |
| `max_active_per_mailbox` | `64` active bridged streams | Reject above cap |
| `accept_timeout` | `15 s` | Fail pending dial with `"timeout"` if unaccepted |
| `idle_timeout` | `300 s` | Close idle streams without activity |
| `write_timeout` | `1 s` | Terminate slow-reader sink without unbounded buffering |

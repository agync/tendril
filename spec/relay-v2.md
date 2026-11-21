# Tendril Stateless WSS Relay Specification v2

Status: **Normative (v2)**

Conventions follow `spec/wire-v2.md`. The relay is an untrusted byte forwarder: it never inspects, decrypts, or logs Tendril plaintext, capability grants, Noise payloads, or endpoint static identities.

---

## 1. Endpoint and Transport

- WebSocket endpoint: `wss://<host>/v2/relay` (`ws://<host>/v2/relay` permitted on loopback `127.0.0.1` / `::1` test fixtures).
- Requests to any other HTTP path MUST be rejected before completing the WebSocket upgrade (note that `/v1/relay` remains served independently per `spec/relay-v1.md` for legacy peers).
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
  "max_frame": 65521      // maximum allowed binary frame byte length
}
```

- Clients MUST canonicalize `challenge.host` (ASCII lowercase, trailing dot stripped, no `:port`, path, userinfo, or control chars; note `canonical(host)` excludes `:port` and represents the hostname only) and MUST verify `canonical(challenge.host) == canonical(dialed_url_host)` (`VerifiedRelayHost`) BEFORE signing any `register`, `dial`, or `accept` proof, preventing cross-relay challenge forwarding attacks.

### 3.1 Blinded Mailbox Registration (Listener Control Socket)

A listening peer registers an ephemeral `mailbox_id` for `epoch` by sending one JSON text frame (`register`):

```jsonc
// Listener -> Server
{
  "op": "register",
  "mailbox_id": string,   // b64url 32-byte per-epoch Ed25519 public key
  "epoch": uint64,        // epoch index covered by this mailbox_id
  "sig": string           // b64url 64-byte strict Ed25519 signature under mailbox_sk
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

### 3.2 Authenticated Dial Request and Pending Notification

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
  "dial_token": string          // b64url 32-byte HMAC-SHA256 capability proof
}
```

If `target_mailbox_id` has an active control connection and fewer than `max_pending_per_mailbox` pending dials, the relay pushes an `incoming` notification over the listener's control WebSocket including the dialer's `challenge.nonce` (`dial_nonce`) and `dial_token`:

```jsonc
// Server -> Listener (control socket)
{
  "op": "incoming",
  "mailbox_id": string,
  "epoch": uint64,
  "conn_id": string,
  "dial_nonce": string,         // b64url 32-byte challenge nonce from dialer's connection
  "dial_token": string          // b64url 32-byte HMAC-SHA256 dial proof
}
```

- Before opening a data socket to accept `conn_id`, the listener MUST validate and record the notification atomically (e.g. via `verify_and_record_v2_relay_dial`):
  1. Look up `epoch` in its active `RelayEpochWindow` (`epoch >= min_valid_epoch`) and verify `dial_token` against `dial_auth_key` over `("tendril-relay-v2-dial\0" || canonical(relay_host) || dial_nonce || mailbox_id || conn_id || epoch_be)` using constant-time comparison (`subtle::ConstantTimeEq`).
  2. ONLY AFTER `dial_token` verifies, check and record `(epoch, dial_nonce, conn_id)` in a bounded `RelayDialReplayCache` to reject replayed `incoming` notifications from a malicious relay. At capacity, `RelayDialReplayCache` evicts only expired epochs (`epoch < min_valid_epoch`) and fails closed without evicting live entries.
- If `dial_token` fails verification, is replayed, or `epoch` is outside the listener's active window, the listener MUST silently ignore the `incoming` notification without opening a data connection or performing a Noise handshake.

### 3.3 Anti-Hijack Stream Accept (Listener Data Socket)

To claim a verified pending `conn_id`, the listener opens a fresh `/v2/relay` WebSocket connection, receives a new `challenge` (`nonce_accept`), verifies `canonical(challenge.host) == canonical(dialed_url_host)`, and sends:

```jsonc
// Listener data socket -> Server
{
  "op": "accept",
  "mailbox_id": string,   // b64url 32-byte epoch mailbox key (MUST match dial.target_mailbox_id)
  "epoch": uint64,        // epoch index (MUST match dial.epoch)
  "conn_id": string,      // b64url 16-byte pending stream identifier
  "sig": string           // b64url 64-byte strict Ed25519 signature under mailbox_sk
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

On valid strict Ed25519 verification and `accept.mailbox_id == pending.target_mailbox_id`, the relay sends `ready` to BOTH the dialer socket and the acceptor socket, then enters raw binary forwarding mode:

```jsonc
{ "op": "ready", "conn_id": string }
```

### 3.4 Error Frames

Control errors prior to binary bridge mode return one JSON text frame and close the WebSocket:

```jsonc
{ "op": "error", "code": string }
```

Standard error `code` values: `"unauthorized"`, `"offline"`, `"rate_limited"`, `"capacity_exceeded"`, `"invalid_request"`, `"timeout"`.

---

## 4. Binary Bridge, Abuse Bounds, and Privacy Guarantees

Once `ready` has been sent, binary forwarding and abuse limits (`max_frame = 65521`, `max_tracked_ips = 4096`, `max_total_connections = 4096`, `max_mailboxes = 1024`, `max_pending_per_mailbox = 8`, `max_active_per_ip = 64`, `max_active_per_mailbox = 64`, `accept_timeout = 15 s`, `idle_timeout = 300 s`, `write_timeout = 1 s`) match `spec/relay-v1.md` Section 3.

### 4.1 Privacy Properties and Epoch Connection Isolation

- **Unlinkability across epochs:** The relay only observes random per-epoch Ed25519 public keys `mailbox_id`. Without `mailbox_secret`, it cannot link `mailbox_id(E)` to `mailbox_id(E + 1)`.
- **Single-socket chaining warning:** Registering multiple epoch `mailbox_id` values `(epoch - 1, epoch, epoch + 1)` on a single persistent WebSocket control connection allows the relay to link consecutive epochs via that shared socket. Clients requiring cross-epoch unlinkability MUST open a separate control WebSocket per epoch `mailbox_id` (and register `epoch + 1` on a fresh socket only within a brief skew margin before the hour boundary). Note also that network-layer IP correlation remains outside the relay mailbox layer unless routed over an anonymous transport.
- **No online enumeration:** An unauthenticated party lacking `mailbox_secret` cannot predict `mailbox_id` or forge a valid `dial_token` for any host.
- **No trusted relay:** End-to-end `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` with v2 pseudonymous reconnect and bucketed inner padding ensures the relay observes neither identity metadata nor plaintext message lengths.

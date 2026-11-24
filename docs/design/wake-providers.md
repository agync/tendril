---
type: Design
title: Opaque wake providers
description: Optional pull-first push wake-hint subsystem using epoch-blinded wake tags, adapter envelopes (UnifiedPush, APNs, FCM, webhook), SSRF-safe HTTP/TLS delivery, and per-target coalescing.
status: stable
tags: [design, runtime, wake, privacy, push]
---

# Opaque wake providers

Tendril uses a pull-first architecture: `tendril-core` remains the sole trust boundary, and every session, pairing handshake, and capability check executes over authenticated `Noise_XXhfs` paths. Optional `WakeProvider` adapters emit opaque push hints to wake sleeping mobile or edge peers so they poll their configured relay or direct paths promptly.

## Pull-first and zero-authority invariant

- **Default no-op:** When no push channel is configured, `NoopWakeProvider` returns `WakeOutcome::Noop` with zero network configuration or I/O. Missing or dropped wake hints fall back seamlessly to standard pull polling.
- **Zero plaintext or identity leakage:** Wake payloads MUST NOT carry plaintext application data, pairing codes, capability grants, `HostHello`, `static_pub`, `signing_pub`, `host_id`, or authorization authority.
- **Best-effort isolation:** `WakeProvider::notify_best_effort` catches transport, DNS, TLS, and timeout errors and returns `WakeOutcome::Skipped` so push relay outages never block or abort core session or pairing workflows.
- **Forged or replayed hints:** Because a wake hint carries no authority, a forged or replayed wake signal at worst triggers one rate-limited outbound reconnect and poll over authenticated Noise paths.

## Epoch-blinded `WakeTag` derivation

To prevent push relays and platform gateways from correlating wake hints to a `host_id`, `signing_pub`, or across time windows, peers share an out-of-band 32-byte `WakeSecret` (zeroized on drop via `ZeroizeOnDrop`) and derive a 16-byte `WakeTag` per quantized 1-hour epoch (`WAKE_EPOCH_SECS = 3600`):

- `epoch = unix_secs / 3600`
- `epoch_s = epoch * 3600`
- `tag_bytes = HKDF-SHA256(ikm = wake_secret, salt = epoch.to_be_bytes(), info = "tendril/wake/epoch-tag/v1")[0..16]`
- `wake_tag = b64url_encode(tag_bytes)`

`WakeTag` values match across peers holding the same `WakeSecret` within the same hour epoch and rotate unlinkably at every hour boundary. Receivers validating incoming wake tags across hour boundaries SHOULD use `verify_epoch_wake_tag_window`, which checks the `+-1` hour epoch window (`epoch - 1`, `epoch`, `epoch + 1`) in constant time to tolerate clock skew.

## Adapter envelopes

`HttpWakeProvider` formats minimal JSON envelopes per `WakeAdapterKind` over HTTP/1.1:

- **UnifiedPush and Webhook:** `{"v": 1, "wake_tag": "<b64url>", "epoch_s": <u64>}` posted to the registered distributor or webhook endpoint.
- **APNs (`WakeAdapterKind::Apns`):** Silent background push (`apns-push-type: background`, `apns-priority: 5`) with `{"aps": {"content-available": 1}, "v": 1, "wake_tag": "<b64url>", "epoch_s": <u64>}` and zero alert, badge, or sound fields. Because `HttpWakeProvider` speaks HTTP/1.1, APNs targets use an HTTP/1.1 push gateway or relay; direct Apple APNs requires HTTP/2 via a custom `WakeProvider` implementation.
- **FCM HTTP v1 (`WakeAdapterKind::Fcm`):** High-priority data-only message `{"message": {"android": {"priority": "high"}, "data": {"v": "1", "wake_tag": "<b64url>", "epoch_s": "<u64>"}}}` with no `notification` block.

Optional bearer tokens attached via `WakeTarget::with_auth_token` reject control characters and render as `"[REDACTED]"` in `Debug` output.

## SSRF, transport, and coalescing rules

- **Endpoint validation (`validate_wake_endpoint_url`):** Requires `https://` everywhere except `http://` on loopback hosts (`localhost`, `127.0.0.0/8`, `::1`). Rejects URLs over 512 bytes, control characters, userinfo credentials, fragments, `metadata.google.internal`, and link-local/metadata IP addresses (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, unspecified).
- **Pre-connect DNS check:** `HttpWakeProvider` resolves socket addresses immediately before connecting and rejects any resolved metadata/link-local address or non-loopback address for `http://` URLs.
- **Bounded timeouts and responses:** Outbound requests enforce `DEFAULT_WAKE_TIMEOUT` (`3s`) and cap HTTP response reads at 4096 bytes.
- **Per-target coalescing (`WakeCoalescer`):** Suppresses duplicate wake hints to the same `(adapter, endpoint)` within `DEFAULT_WAKE_COALESCE_INTERVAL_SECS` (`5s`), bounded to `MAX_WAKE_COALESCE_TARGETS` (`1024`) entries with oldest-entry eviction.

## Wake around a connect

A wake never replaces the connect. Every surface runs the same policy connect used for Day-2 connects (`connect_with_policy_and_store`), so a woken connect negotiates `route_seq`, ingests `0x0C` route sets from the host, accepts a recovery URI and applies the route policy exactly as a connect without a wake does. No surface runs a separate legacy dial before or after it.

| `pre_wake` | Order | Retries |
|---|---|---|
| `true` | The wake hint goes out first, then the connect runs. | Up to `max_attempts` connects, `retry_delay` apart, while each failure is a wakeable miss. |
| `false` (default) | The connect runs once. Only a wakeable miss sends the wake hint. | After the hint, the same retry loop as above. Any other failure ends the dial at once and never sends a hint. |

Whether a failure is a wakeable miss is decided by one typed predicate, `AttemptError::is_wakeable_miss`, never by message text. It is true for an attempt that did not commit and whose error and every candidate failure is one of:

- a transport miss: I/O error, timeout, or a closed stream;
- a typed relay `offline` refusal (`RuntimeError::RelayOffline`): the relay answered that the peer's mailbox holds no registration. The `/v1/relay` dial, the `/v2/relay` dial and the Day-2 "every relay candidate offline for the pinned key" case each have their own kind, with unchanged display text.

Everything else is final and is not retried: a connect that committed (a session was established and the final authorization check or its transaction failed), a key, pin, revocation or grant failure, a relay admission refusal, an egress refusal, and a protocol failure such as no dialable stored routes. A hint is sent at most once per connect. `max_attempts` is the number of connects after the first miss (default `10`, never below `1`), so with `pre_wake` off up to `max_attempts + 1` connects can run, `retry_delay` defaults to `100 ms`, and the hint is bounded by `wake_timeout` (`3 s`). The hint's own outcome (`Delivered`, `Coalesced`, `Noop` or `Skipped`) never fails the connect.

| Surface | Where the wake runs |
|---|---|
| CLI | `dial --wire-v2 --endpoint <E> --wake-url <U>`. `--pairing-uri` and `--replace-routes` apply to the woken connect. |
| C ABI, Go, Swift, Kotlin | `tendril_session_connect_v2` or `tendril_session_connect_with_options` with `"wire": 2` and an explicit endpoint, on an endpoint with a configured wake target. |
| Python, Node | `connect_v2` / `connectV2` or `connect_with_options` / `connectWithOptions` with `wire` 2 and an explicit endpoint, on an endpoint configured with `wake_url`. |
| Browser | None. The browser SDK has no wake provider. |

A connect without an endpoint, or over Wire v1, never wakes: a wake needs the explicit endpoint that names where the sleeping peer will answer.

## CLI and FFI configuration

- **CLI flags (`tendril`):** `dial` accepts `--wake-url` (requires `--wire-v2`), `--wake-adapter <webhook|apns|fcm|unified-push>` (default `webhook`), `--wake-secret-file` (or `TENDRIL_WAKE_SECRET`), `--wake-auth-header-file`, and `--wake-pre-wake` to send the opaque wake hint before the first connect instead of after a wakeable miss. `--wake-url` requires `--endpoint`, and `--wake-secret-file`, `--wake-auth-header-file` and `--wake-pre-wake` require `--wake-url`. `--pairing-uri` and `--replace-routes` work with a wake: the woken connect is the recovery-URI policy connect described in [Seamless pairing defaults](../usage/seamless-pairing.md#recovery-by-a-fresh-qr). Secret files enforce regular non-symlink files `<= 16 KiB` with Unix `0600` (`mode & 0o077 == 0`) permissions.
- **FFI (`tendril-ffi`):** `tendril_endpoint_configure_transports_json` configures wake-provider targets (`wake_url`, `wake_adapter`, `wake_secret_b64`, `wake_auth_token`, `wake_pre_wake`, `wake_retry_delay_ms`, `wake_max_attempts`, `wake_timeout_ms`) alongside managed relay/P2P transport credentials on a `TendrilEndpoint` without passing inline secrets on the command line. Python and Node take the same keys (Node also in camelCase, for example `wakePreWake`); setting any `wake_*` key without `wake_url` is rejected, as is `wake_url` without `wake_secret_b64`.

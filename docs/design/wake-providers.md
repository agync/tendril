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

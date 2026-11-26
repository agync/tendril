---
type: Log Entry
title: "Add direct HTTP/2 APNs wake provider and MutableAlert mode"
description: "Add direct HTTP/2 APNs wake transport, MutableAlert loc-key payloads, WebPKI TLS roots, and shared WakeTransportSettings."
tags: [log, update]
kind: Update
status: stable
---

# Add direct HTTP/2 APNs wake provider and MutableAlert mode

Added direct Apple HTTP/2 APNs wake delivery, `MutableAlert` static localization-key payloads, default WebPKI root verification on `HttpWakeProvider`, and shared `WakeTransportSettings`:

- **Runtime (`tendril-runtime`):** Split `wake` into `wake/mod.rs` and `wake/apns_h2.rs`; loaded `webpki-roots` by default in `HttpWakeProvider::new()` (adding `HttpWakeProvider::with_empty_roots()` for negative tests); added `ApnsPushMode::MutableAlert` with `validate_apns_loc_key` (`1..=64` ASCII `[A-Za-z0-9_.-]`); implemented `ApnsH2WakeProvider` (`WakeAdapterKind::ApnsH2`) with SSRF checks, ALPN `h2` TLS, pooled `h2::client::SendRequest` per `(host, port)` with `GOAWAY` recovery, and ES256 `.p8` JWT caching (`2700` s) alongside bearer token and mTLS auth; added `WakeConfigSpec`, `WakeTransportSettings`, and `build_wake_provider`.
- **CLI & Docs (`tendril-cli`, `docs/design/wake-providers.md`):** Wired `tendril dial` (`--wake-apns-mode`, `--wake-apns-topic`, `--wake-apns-loc-key`, `--wake-apns-team-id`, `--wake-apns-key-id`, `--wake-apns-p8-file`) and `tendril-conformance-peer` to persist one `WakeTransportSettings` provider per endpoint instead of creating per-dial `HttpWakeProvider` instances.

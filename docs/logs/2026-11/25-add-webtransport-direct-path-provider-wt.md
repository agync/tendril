---
type: Log Entry
title: "Add WebTransport direct path provider (wt://)"
description: "Add opt-in WebTransport (HTTP/3 over QUIC) direct path transport under ProviderId::Direct."
tags: [log, update]
kind: Update
status: stable
---

# Add WebTransport direct path provider (`wt://`)

Added opt-in WebTransport (HTTP/3 over QUIC) as an authenticated direct path transport (`wt://<host>:<port>[/<path>][?certhash=<43-char-b64url-sha256>]`) under `ProviderId::Direct` (rank 1):

- **Core (`tendril-core`):** Validated `wt://` endpoints, explicit ports, and `?certhash=` 32-byte digests; classified `wt://` under `ProviderId::Direct`; supported LAN/loopback `lan2_group` checks and `"wt"` redaction.
- **Runtime (`tendril-runtime`):** Added optional `webtransport` feature (`wtransport 0.7.2`, off in `tendril-ffi` default features), `WtListener` (10-day ECDSA self-signed cert) and `WtDialer` (`resolve_checked` single-lookup DNS pinning + `serverCertificateHashes`), and `SkipReason::WebtransportFeatureDisabled`.
- **CLI & Browser (`tendril-cli`, `tendril-wasm`, `@tendril-sdk/web`):** Added `--webtransport` to `tendril serve`, `serve_wt` in `tendril-conformance-peer`, `dialWtStream` (`WtStreamOptions`), `isRelayTarget`, and Chrome E2E verification pairing and dialing `provider: "direct"` ahead of relay.

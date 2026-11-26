---
type: Log Entry
title: "relay: ticket expiry, replaced registrations, and allowlist key checks"
description: "relay: ticket expiry, replaced registrations, and allowlist key checks"
tags: [log, update]
kind: Update
status: stable
---

relay: ticket expiry, replaced registrations, and allowlist key checks

Both relays (`tendril-relay` and the Cloudflare Workers relay) now end a ticket-admitted registration and its standby sockets once the relay clock passes `not_after + 30 s`, while streams bridged before then run until they close. A replaced registration fails its pending dials with `offline` at once and receives the new `replaced` error code; `RelayListener::accept` and `RelayV2Listener::accept` return `Closed` without re-registering, their standby pools stop, and `was_replaced` reports the takeover. Expiry is also checked when a dial, standby, accept, or new registration arrives, so expired state is never used while its teardown is pending and an expired registration is never told `replaced`, and a replaced registration's pending dials leave the relay tables at once. `RelayListener` now pings its control socket and ends after `90 s` of silence. The `tendril-relay` CLI validates `--allow-mailbox` and `--allow-mailboxes-file` keys as Ed25519 points, and both relays default `auth_scope` to `register-only` when a mailbox allowlist is the only admission control and refuse to start with an explicit `all` in that case. See `spec/relay-v1.md` Sections 2.2, 2.4, and 2.5.

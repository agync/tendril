---
type: Log Entry
title: "Add relay standby acceptor pools and 0-RTT fast-open"
description: "Add pre-authenticated standby acceptor sockets and 0-RTT Dial.init_frame delivery across /v1/relay, /v2/relay, tendril-runtime drivers, and @tendril-sdk/web."
tags: [log, update, relay, runtime, web]
kind: Update
status: stable
---

# Add relay standby acceptor pools and 0-RTT fast-open

- Added optional `Challenge.{fast_open, standby}`, `Register.fast_open`, `op = "standby"` / `standby_ready` (capped at `MAX_STANDBY_PER_MAILBOX = 4`), and `Dial.init_frame` / `Incoming.init_frame` across `/v1/relay` (`spec/relay-v1.md`) and `/v2/relay` (`spec/relay-v2.md`), preserving zero mailbox presence leakage and clean fallback when standby pools are empty or peers omit capability flags. See [Stateless relay v1 and async runtime providers](../../design/relay-and-runtime.md) and [Wire v2 privacy profile and PAKE](../../design/wire-v2-privacy.md).
- Added replenished `STANDBY_POOL_SIZE = 2` acceptor pools in `RelayListener` and the current center epoch of `RelayV2Listener`, `PathDialer::dial_with_init`, and 0-RTT initial frame delivery across `SessionDriver`, `V2SessionDriver`, and pairing policy drivers.
- Added `initFrame` and `RelayStream.fastOpenSent` in `@tendril-sdk/web` so browser `pair`, `connect`, `connectV2`, and `enroll` send initial `preamble || msg1` bytes inside `Dial` whenever `Challenge.fast_open === true`. See [Web and mobile bindings](../../reference/web-and-mobile.md).

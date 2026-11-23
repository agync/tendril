---
type: Log Entry
title: "ffi: group hub serves /v2/relay sibling links"
description: "The FFI group hub now passes the endpoint's relay auth and registers each group's relay mailboxes, so FFI endpoints link over /v2/relay siblings and leave app-served /v1/relay mailboxes alone."
tags: [log, update]
kind: Update
status: stable
---

ffi: group hub serves /v2/relay sibling links:

**Behaviour change for existing FFI apps:** the group hub now registers relay mailboxes for the endpoint's identity and its groups, where before it registered none. An app that serves `/v1/relay` must let every `tendril_endpoint_serve_relay` call return before its first `tendril_group_open`; a relay served later is not known to the hub, which can then register the identity mailbox on that relay host and displace the app's own mailbox.

- **Wiring (`crates/tendril-ffi/src/lib.rs`, `ensure_group_runtime`):** the hub's `GroupPoolConfig` now carries the endpoint's relay auth (`with_relay_auth`) and `relay_listen` (`with_relay_listen(true)`), because the endpoint hub is the serving runtime of the identity, like `tendril serve`. No C ABI change.
- **v1 rule:** `tendril_endpoint_serve_relay` records each URL it registers the identity mailbox on, and the hub passes that list as `served_v1_relays` when it starts, so a pool never registers the identity mailbox on a relay host the app already serves. The list is read once, when the hub starts, and the match is by canonical host: every successful `tendril_endpoint_serve_relay` call must return before the first `tendril_group_open`. `tendril_endpoint_serve_relay_v2` needs no entry: its ordinary pair mailboxes differ from the group mailbox.
- **Refresh without an inbound stream:** the hub opens a pool for every stored group when it starts, inside the endpoint runtime, and each pool's book watcher reconciles its relay registrations on its 250 ms tick. The new test registers the root's group mailbox with no stream reaching either endpoint. Hub discovery runs only when the hub starts and on each `tendril_group_open`: a group stored later, or one whose pool failed to open (such as an unresolvable root CRL), is reachable only after another `tendril_group_open`, and no watcher retries it.
- **Docs:** the "does not yet register or pass relay auth" clause is replaced in `docs/design/groups.md` (Dialers row, v1 relay identity mailbox row) and `docs/reference/ffi-and-bindings.md` (Relay limits).
- **Tests (`crates/tendril-ffi/tests/group_ffi.rs`):** `ffi_group_hub_serves_and_dials_v2_relay_with_relay_auth` links two FFI endpoints over `/v2/relay` on an auth-required embedded relay and exchanges group data through the C ABI (fails without the relay auth or `relay_listen`); `ffi_group_hub_leaves_a_served_v1_relay_mailbox_to_the_app` keeps an ordinary session arriving through an app-served `/v1/relay` mailbox while the group names that relay and a second, unserved relay. The pool's registration of the identity on the unserved relay is the control; with only `with_served_v1_relays` removed the test fails, because the pool displaces the app's mailbox. The accept thread is scoped and joined before any assertion.

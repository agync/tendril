---
type: Log Entry
title: "Document small peer mesh groups"
description: "Add the groups design page and cover groups in the CLI, FFI, web, mobile, wire, and overview docs."
tags: [log, update]
kind: Update
status: stable
---

Document small peer mesh groups:

- **Design (`docs/design/groups.md`):** New page on signed manifests, root and co-admins, first-contact pinning, revocation with rendezvous-key rotation, the `GroupPool` and `GroupHub` runtime, bounds, and known limits. The hub runs on `tendril serve` and FFI endpoints only; Python and Node `group_open` use standalone pools that accept siblings on their own `listen_addr`. Linked from the design index.
- **Design (`docs/design/wire-and-pairing.md`, `docs/design/wire-v2-privacy.md`):** Describe frames `0x0A` and `0x0B`, `SessionHello.groups`, and the Wire v2 bootstrap to pairwise secret upgrade.
- **Usage (`docs/usage/cli-demo.md`):** Add a peer groups section covering `group create|add|remove|sync|broadcast|list|show`, the group events `tendril serve` prints, which dialers each command uses, and the `--p2p` opt-in. `tendril serve` pins an unknown group only from the manifest signer as an `Active` paired peer, routes each inbound session after the handshake to the advertised group's pool or the ordinary path, and keeps group siblings out of the roster.
- **Reference (`docs/reference/ffi-and-bindings.md`):** Add the `tendril_group_*` C ABI, error mapping, group and session event JSON, ownership rules, a per-language surface table, the host-driven polling and pool close behaviour, p2p dialer rules, and the `/v2/relay` sibling limit.
- **Reference (`docs/reference/web-and-mobile.md`):** Add `WasmGroupBook` and the member-only `TendrilWebGroup`, Android and iOS notes on sealed endpoints, and the Swift and Android verification prerequisites.
- **Overview and architecture (`docs/overview.md`, `docs/index.md`, `docs/architecture/layers.md`):** Mention groups where features are listed.

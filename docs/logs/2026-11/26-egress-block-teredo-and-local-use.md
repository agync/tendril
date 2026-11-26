---
type: Log Entry
title: "egress: block Teredo and local-use NAT64 in runtime and Web SDK"
description: "egress: block Teredo and local-use NAT64 in runtime and Web SDK"
tags: [log, update]
kind: Update
status: stable
---

egress: block Teredo and local-use NAT64 in runtime and Web SDK

- `classify_destination` in the runtime egress policy now returns `Blocked` for Teredo `2001::/32`, matching the pairing URI parser. Neighbouring public space such as `2001:4860::1` stays `Public`.
- The Web SDK relay URL check rejects Teredo `2001::/32` and local-use NAT64 `64:ff9b:1::/48` hosts.

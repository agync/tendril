---
type: Log Entry
title: "runtime: share one wake-and-retry loop across the CLI, C ABI, Python, and Node"
description: "runtime: share one wake-and-retry loop across the CLI, C ABI, Python, and Node"
tags: [log, update]
kind: Update
status: stable
---

runtime: share one wake-and-retry loop across the CLI, C ABI, Python, and Node

Add `tendril_runtime::connect_with_wake`, generic over the result and error type with a caller-supplied classifier, plus `connect_with_wake_policy` for policy connects. The CLI Wire v2 dial, the C ABI, Python, Node, and `wake_and_dial_v2` call it instead of keeping their own copies. Behavior is unchanged: a miss a wake can fix sends one best-effort hint, then up to `max_attempts` connects run `retry_delay` apart; any other failure ends the dial without a wake.

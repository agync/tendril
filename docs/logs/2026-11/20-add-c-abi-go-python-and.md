---
type: Log Entry
title: "Add C ABI, Go, Python, and Node bindings with conformance suite"
description: "Added callback-free tendril-ffi C ABI, thin Go, Python, and Node bindings verified against conformance vectors and live peer interop, plus Gate #7 baselines."
tags: [log, update]
kind: Update
status: stable
---

Add C ABI, Go, Python, and Node bindings with conformance suite:

- Added [FFI ABI and cross-language bindings](../../reference/ffi-and-bindings.md) covering `tendril-ffi` (`crates/tendril-ffi/include/tendril.h`), Go cgo (`bindings/go`), Python PyO3 (`bindings/python`), Node `napi-rs` (`bindings/node`), and Gate #7 baselines.

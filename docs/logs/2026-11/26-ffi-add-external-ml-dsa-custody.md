---
type: Log Entry
title: "ffi: add external ML-DSA custody, extension profile, and APNs wake"
description: "ffi: add external ML-DSA custody, extension profile, and APNs wake"
tags: [log, update]
kind: Update
status: stable
---

ffi: add external ML-DSA custody, extension profile, and APNs wake

Add `TendrilMlDsa65Signer` external ML-DSA-65 custody, `tendril_endpoint_new_sealed_with_options` (supporting the compact `extension` runtime profile and fail-closed `client_only` mode), and `tendril_verify_wake_tag` across the C ABI, Go, Python, and Node bindings. Wire persistent endpoint-owned `WakeProvider` instances via `build_wake_provider` supporting direct HTTP/2 APNs (`apns_h2`), `mutable_alert`, and `wake_coalesce_secs` (with camelCase aliases in Node).

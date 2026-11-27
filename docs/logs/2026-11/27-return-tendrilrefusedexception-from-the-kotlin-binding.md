---
type: Log Entry
title: "Return TendrilRefusedException from the Kotlin binding"
description: "The Kotlin JNI layer throws TendrilRefusedException for an authenticated refusal, the closed event carries it, and the endpoint gains revoke options, a refusal policy and notice removal."
tags: [log, update]
kind: Update
status: stable
---

Expose authenticated refusal through `bindings/kotlin`. When a native call fails, the JNI layer reads `tendril_last_error` and `tendril_last_error_code` back to back on the failing thread, and a code that starts with `refused` throws `dev.tendril.TendrilRefusedException(reason, closeCode)`, a subclass of `IllegalStateException`, so existing catches keep working. A refused Wire v2 connect throws it, and so do `sendData`, `rekey` and `closeSession` on a session the host ended. A refused Wire v1 connect returns first, and the `closed` event carries `refusal`; `closedEventRefusal` turns it into the same exception.

`TendrilEndpoint` gains `revokePeerWithOptions(peerId, notify)`, `setRefusalPolicy(pending, revokedNoticeTtlSecs)` and `clearRefusalNotice(peerId)`. A `consumer-rules.pro` keeps the exception class under R8, because native code builds it by name and R8 must not rename it. `refused_revoked` means the host blocks this device key permanently and re-pairing needs a new device identity; `refused_pending` means retry with backoff. See [FFI ABI and cross-language bindings](../../reference/ffi-and-bindings.md#kotlin-bindingskotlin).

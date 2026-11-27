---
type: Log Entry
title: "Expose authenticated refusal in the C ABI and Go binding"
description: "The C ABI reports a refusal as TENDRIL_ERR_REFUSED with a stable last-error code, the closed event names it, and the Go binding returns a RefusedError."
tags: [log, update]
kind: Update
status: stable
---

Expose authenticated refusal through `tendril-ffi` and `bindings/go`. `tendril_last_error_code` reports the stable code of the last error on the thread (`refused_revoked`, `refused_pending`, `refused`, or another runtime code, `""` when untyped) with the contract of `tendril_last_error`. A refusal returns the new `TENDRIL_ERR_REFUSED` (`-8`): a refused Wire v2 connect returns `NULL` with the code set, and `tendril_session_send_data`, `tendril_session_rekey` and `tendril_session_close` return it on a session the host ended with a refusal (`tendril_session_poll_event` delivers a `closed` event with `refusal` set, then `TENDRIL_EOF`), where they returned `TENDRIL_ERR_PROTOCOL` before. The `closed` event gains `refusal` (`"revoked"`, `"pending"`, `"other"` or `null`, initiator sessions only).

`tendril_endpoint_revoke_peer` now records a refusal notice per the endpoint policy. `tendril_endpoint_revoke_peer_with_options`, `tendril_endpoint_set_refusal_policy_json` and `tendril_endpoint_clear_refusal_notice` expose the notify choice, the persisted policy and notice removal. The CLI `attempt_failed` line reports `refused_*` as `error_code`. The Go binding returns a `*RefusedError` from `ConnectV2`, `SendData`, `Rekey` and `CloseSession` that `errors.As` matches, exposes a closed event's refusal through `SessionEvent.Refused`, and reads the message and the code inside the same locked OS thread as the failing call. See [FFI ABI and cross-language bindings](../../reference/ffi-and-bindings.md#authenticated-refusal).

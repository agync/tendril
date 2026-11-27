---
type: Log Entry
title: "identity: stored host_id is checked, responders refuse invalid ids"
description: "A supplied host_id is validated and compared with an existing identity.json, empty ids are refused by the CLI and conformance peer, runtime responders refuse an invalid local host_id, and with_host_id is test-only."
tags: [log, update]
kind: Update
status: stable
---

identity: stored host_id is checked, responders refuse invalid ids:

- `StateStore::load_or_generate_identity` validates a supplied `host_id` before it looks at `identity.json`, and refuses one that differs from an existing identity instead of ignoring it. `tendril init --host-id ""` and the conformance peer refuse an empty `host_id`; the C ABI, Python and Node keep treating an empty one as unset.
- The v1 and v2 session responders and the v1 pair and v2 PAKE pair responders in `tendril-runtime` refuse an invalid local `host_id` before touching the stream. `WasmIdentity` refuses to serialize one in its byte form as well.
- `EndpointIdentity::with_host_id` exists only for tests (`cfg(test)` or the `test-utils` feature); `tendril-runtime` and `tendril-wasm` enable the feature for their tests.
- The C ABI enrol pre-persist reads the in-memory CRLs under the roster file lock and resolves the key of a revoked trust anchor's CRL from the anchor record, so that CRL is persisted too.

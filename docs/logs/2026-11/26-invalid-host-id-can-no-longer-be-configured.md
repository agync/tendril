---
type: Log Entry
title: "identity: an invalid host_id can no longer be configured"
description: "Every production caller configures a local host_id through EndpointIdentity::try_with_host_id, so no endpoint, identity file or responder carries an id that peers refuse."
tags: [log, update]
kind: Update
status: stable
---

identity: an invalid host_id can no longer be configured:

- `EndpointIdentity::try_with_host_id` returns an error for a `host_id` that fails `is_valid_host_id`; `with_host_id` stays unchecked, for literals and tests that forge a hostile host.
- `StateStore::load_or_generate_identity`, the C ABI, Python, Node, the WASM identity and the conformance peer use `try_with_host_id`, so an invalid `host_id` is an error at configuration and nothing is written. `serialize_identity_json` refuses to persist one, and persisted identities were already validated on load, so `tendril serve` and every other responder refuse to start with an invalid local `host_id`.
- Updated `spec/pairing-v1.md` Section 5.

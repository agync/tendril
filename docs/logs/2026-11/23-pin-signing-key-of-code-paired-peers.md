---
type: Log Entry
title: "Pin the signing key of code-paired peers"
description: "Human pairing claims carry the initiator's hybrid signing key with a channel-bound proof, so code-paired peers can join groups."
tags: [log, update]
kind: Update
status: stable
---

Pin the signing key of code-paired peers:

- **Protocol (`spec/pairing-v1.md` Section 4.1, `spec/wire-v1.md`, `spec/wire-v2.md`):** A human `PairClaim` carries `signing_pub` and an `enroll_proof` signed over `"tendril-pair-key-v1\0" || h || initiator static_pub`. The responder verifies it after the code burns. A key claimed for an `active` entry without a key returns it to `pending` until the new SAS is confirmed; a key that differs from one pinned for the same static key is refused, and a keyless claim cannot replace the SAS of an unconfirmed key. Wire v1 responders built before this change reject a keyed claim (pre-1.0 break); Wire v2 responders ignore it. Keyed v2 `msg3` pads to the `16384` bucket.
- **Vectors (`spec/vectors/pairing_mac.json`):** New `key_proof` case, checked in Rust and Go.
- **Design and reference (`docs/design/groups.md`, `docs/design/wire-and-pairing.md`, `docs/reference/ffi-and-bindings.md`, `docs/reference/conformance-vectors.md`, `docs/usage/cli-demo.md`):** Remove the code-paired peers limitation and describe the key claim and the re-pair path for older entries.

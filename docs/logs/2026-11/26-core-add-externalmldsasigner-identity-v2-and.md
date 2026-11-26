---
type: Log Entry
title: "core: add ExternalMlDsaSigner, identity v2, and ADR 0005"
description: "core: add ExternalMlDsaSigner, identity v2, and ADR 0005"
tags: [log, update]
kind: Update
status: stable
---

core: add ExternalMlDsaSigner, identity v2, and ADR 0005:

- Added `ExternalMlDsaSigner`, `SigningKeypair::from_ed25519_and_external`, `mldsa_seed_bytes_opt`, and `is_external_mldsa` in `tendril-core`, enforcing post-sign `HybridSigningPublicKey::verify` self-checks on external outputs, rejecting `sign_deterministic` with `CoreError::ProtocolViolation`, and forbidding `External -> Software` custody downgrades in `EndpointIdentity::rotate`.
- Extended `tendril-runtime::store::PersistedIdentity` with `version: 2` external custody persistence (`pq_signing_custody: "external_mldsa65"`, `pq_signing_pub_b64`), `deserialize_identity_json_with_signer`, and `StateStore::load_or_generate_identity_with_signer` using constant-time `ct_eq` key matching while preserving strict `version: 1` compatibility.
- Recorded [ADR 0005](../../adr/0005-apple-custody-wake-and-extensions.md) covering Tier 1+2 Secure Enclave custody (`D1=B`), remote SwiftPM distribution (`D2=B`), direct HTTP/2 APNs with `mutable-content: 1` fallback (`D3=2`), and `S1-S6` normative invariants across Waves 1-4.

---
type: Log Entry
title: "Add Phase 6 M2M enrollment, single-use burn log, and v2 privacy ADR"
description: "Phase 6 M2M enrollment profile, single-use burn log, grant purpose separation, log redaction, and v2 privacy profile ADR."
tags: [log, update]
kind: Update
status: stable
---

# Add Phase 6 M2M enrollment, single-use burn log, and v2 privacy ADR

Documented Phase 6 autonomous Machine-to-Machine (M2M) enrollment and audit hardening across `spec/`, `docs/`, core state machines, runtime, CLI, and C FFI:

- Added [Machine-to-machine enrollment](../../design/m2m-enrollment.md), detailing opt-in responder policy (`serve --allow-enroll`), mandatory initiator host pinning (`PinnedHost`), `tendril-enroll-v1\0` Ed25519 channel-binding proofs, trust anchor management (`anchor add`/`revoke`/`list`), atomic persistent `burned_enrollment_nonces` replay rejection (`16_384` bounded slots), and automatic self-CRL re-signing (`Roster::resign_crl`) on `tendril rotate`.
- Documented grant purpose separation (`uses == 0` rejection everywhere, `uses`/`machine` exclusion on session grants) and fail-closed SAS confirmation (`pair.confirm` requires `--sas` unless opting in with `--allow-no-sas`) in [Capability grants and revocation](../../design/grants.md) and [Reference CLI, relay deployment, and conformance peer](../../usage/cli-demo.md).
- Documented operator stdout log redaction (`serve --redact-logs`) and added [ADR 0003 V2 privacy profile](../../adr/0003-v2-privacy-profile.md) scoping epoch-blinded relay mailboxes, pseudonymous handshake metadata, bucketed inner frame padding, and jittered keepalive/rekey timing for Phase 7+.
- Added canonical vectors (`spec/vectors/m2m_enrollment.json`), Rust/Go vector verification, C ABI helpers (`tendril_endpoint_{add_trust_anchor,revoke_trust_anchor,mint_enrollment_token,enroll_initiate}`), and end-to-end CLI/FFI M2M tests.

---
type: Design
title: Machine-to-machine enrollment
description: Autonomous headless device enrollment via trust anchors, channel-bound hybrid Ed25519 + ML-DSA-65 proofs, atomic single-use nonce burning, and default-deny grants.
status: stable
tags: [design, pairing, m2m, security]
---

# Machine-to-machine enrollment

Machine-to-machine (M2M) enrollment allows headless servers, CI runners, and workload agents to pair without interactive human Short Authentication String (SAS) comparison while preserving `Noise_XXhfs` key authentication, default-deny capability isolation, and single-use replay resistance.

## Threat model and prerequisites

- **Opt-in responder policy:** M2M enrollment is disabled by default (`EnrollmentPolicy::default().enabled == false`). Hosts enable it explicitly via `serve --allow-enroll` in `tendril-cli` or by registering active trust anchors or minting self-targeted enrollment tokens across `tendril-ffi`, Go, Python, Node.js, Android Kotlin JNI, and Apple Swift (while revoking the last active anchor with no self-issued token returns the host policy to disabled/`unauthorized`). On the sans-I/O browser SDK, `WasmIdentity`, `WasmRoster`, `WasmPairInitiator`, and `TendrilWebClient.{addTrustAnchor, revokeTrustAnchor, mintEnrollmentToken, enroll}` provide initiator enrollment, token minting, and roster trust-anchor management.
- **Mandatory out-of-band initiator pinning:** Initiators MUST hold a `PinnedHost` (`host_id`, static X25519 key, hybrid signing key pin `SigningKeyPin` as either the full `1984`-byte public key or its `32`-byte SHA-256 hash, and `rotation_seq`) and verify `HostHello.signing_pub` (and any `RotationRecord` chain) in `msg2` before sending `msg3`. Unpinned Trust On First Use (TOFU) is forbidden in M2M mode.
- **Channel-bound proof (`enroll_proof`):** In `msg3`, the initiator sends a `PairClaim` carrying `enrollment_token`, `signing_pub` (`1984`-byte hybrid public key), and `enroll_proof` (`3373`-byte hybrid `Ed25519 || ML-DSA-65` signature with context `"tendril-hybrid-v1"` over `"tendril-enroll-v1\0" || h || peer_static_pub || UTF-8(token.nonce)`), binding the token to the exact handshake transcript and peer identity.

## Token rules and trust anchors

An enrollment token is an RFC 8785 JCS signed `Grant` (`uses: 1`, `machine: true`, 16-byte `b64url` `nonce`, short expiry bounded by responder policy, default `900 s`, hard ceiling `86400 s`) holding exclusively `pair.enroll` or host-scoped `pair.enroll:<host_id>`. Application capabilities (`fs.read`, `pair.mint`, etc.) are rejected on enrollment tokens, and `verify_grant_with_chain` / `authorize_grant` reject any grant specifying `uses` or `machine` during `intent = session` authorization.

Responders verify the root signer against either the responder itself (when `allow_self_issued` is enabled) or an active external `TrustAnchor` registered in `Roster`. Revoking a trust anchor propagates across sibling anchors or peers sharing its `signing_pub`. When delegated via `delegated_from`, intermediate links must hold `pair.mint`, omit `uses` and `machine`, and pass active CRL checks (`revoked_devices`, `revoked_nonces`).

## Atomic burn log and rotation automation

To stop concurrent replay races across workers or subprocesses, responders persist a bounded `burned_enrollment_nonces` log (`MAX_BURNED_ENROLLMENT_NONCES = 16_384`, pruning expired entries where `not_after <= now`) with `Roster` under `.roster.lock`. In `tendril-runtime`, `msg3` claim processing executes inside the roster lock (`StateStore::update_roster`), burning the nonce and persisting `Roster` before returning `PairResponse` (`status: "active"`). If the presenting static key is `Revoked`, enrollment fails closed (`revoked`) while keeping the nonce burned.

Peers enrolled through M2M enter `Active` state with zero application grants; `pair.mint` remains a separate step. Rotating host keys with `tendril rotate` automatically re-signs any persisted self-issued `RevocationList` via `Roster::resign_crl` so previously revoked token nonces remain enforced across key rotation. Normative details live in `spec/pairing-v1.md` Section 7 and `spec/vectors/m2m_enrollment.json`.

## Day-2 routes from the enrollment reply

An enrolled machine must be able to reach the host again after a restart without a manually configured route. The initiator requests the host's announced route set by sending `PairClaim.route_seq`, and the host returns it in `PairResponse.route_set`, hybrid-signed by the same key the initiator verified at `msg2`. The initiator checks structure, key binding and both signature halves before it trusts the set. A set that fails any check is dropped with a typed warning (`malformed`, `key_mismatch`, `bad_signature`) and the enrollment still succeeds, because the token is already burned and both keys are proven.

In `tendril-runtime`, only `drive_m2m_enroll_initiator_with_routes` requests and stores routes, with explicit options (route policy and operator endpoint). It checks the pin against the local roster before the handshake, replaces a pin older than the stored entry with the stored keys, and defers the claim so the host that `msg2` authenticated is dry-run through the pin write before `msg3`; a local conflict therefore never spends the token. It then pins the host as `Active`, applies a verified set as `signed` routes and, unless the route policy is `none`, stores the operator endpoint as the `committed` route, all in one roster transaction. The endpoint never sticks: a re-enrollment through a new address, or an explicit operator route update, replaces it. On Day 2 `operator` routes sort ahead of every rung; for the rest the rung comes first and the source (`signed`, then `committed`, then URI hints) breaks ties inside a rung, ahead of the `/v2/relay` and IP literal preferences. The driver returns route problems as typed warnings. `drive_m2m_enroll_initiator_with_store` requests no route set and stores no route, exactly as before this change, and only pins the host.

Every surface calls the routes driver with its own route policy and the endpoint exactly as the operator gave it: `tendril enroll` (`--route-policy`, default `all-signed`), `tendril_endpoint_enroll_initiate` and the Python and Node `enroll_initiate` (the `route_policy` transport key, default `all_signed`). Their result JSON adds `routes_persisted` (the stored routes, `[]` under `none`) and `route_warnings` (reasons a route was not stored; the enrolment still succeeded). An endpoint with no state directory (memory-only) has no store to hold routes, so it requests none and stores none whatever its route policy, pins the host in memory, and reports `routes_reason: "no_state_dir"`; give the endpoint a state directory to learn Day-2 routes at enrolment.

Hosts and initiators built before this change parse these messages with unknown fields rejected. A host sends the set only when the claim requested it, and an older host rejects a requesting claim as `protocol_error` before it burns the token. The full rules are in `spec/pairing-v1.md` Section 7.5.

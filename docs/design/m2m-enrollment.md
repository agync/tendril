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

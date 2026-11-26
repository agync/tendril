# Decisions

Architecture decision records, one decision per page.

- [0001 One core, hostile paths](0001-one-core-hostile-paths.md) - Single Rust core with thin bindings, untrusted path providers, and separated pairing confirmation and capability grants.
- [0002 V1 protocol profile and Sans-I/O core](0002-v1-protocol-profile-and-sans-io-core.md) - Frozen Tendril v1 wire domain separators, transcript-bound pairing proof and SAS, humane retry limits, Sans-I/O core split, and minimal stateless WSS relay protocol.
- [0003 V2 privacy profile](0003-v2-privacy-profile.md) - Planned v2 protocol enhancements for blinded epoch relay mailboxes, pseudonymous handshake metadata, bucketed inner padding, and jittered keepalive/rekey timing.
- [0004 Hybrid post-quantum cryptography in v1](0004-hybrid-post-quantum-v1.md) - Mandatory `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` key exchange and hybrid `Ed25519 + ML-DSA-65` signatures directly in pre-1.0 wire v1.
- [0005 Apple Secure Enclave custody, wake transport, and extensions](0005-apple-custody-wake-and-extensions.md) - Tier 1+2 Secure Enclave key custody (`D1=B`), remote SwiftPM binary distribution (`D2=B`), direct HTTP/2 APNs with `mutable-content: 1` fallback (`D3=2`), and `S1-S6` extension hardening invariants.

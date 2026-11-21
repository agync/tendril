# Design

Normative protocol design covering framing, pairing, key rotation, and capability authorization.

- [Wire protocol and pairing](wire-and-pairing.md) - Preamble framing, Noise XXhfs hybrid PQ handshake, transcript-bound pairing proof, hybrid key rotation chains, and inner encrypted transport frames.
- [Machine-to-machine enrollment](m2m-enrollment.md) - Opt-in headless enrollment using signed single-use tokens, hybrid Ed25519 + ML-DSA-65 transcript proofs, external trust anchors, and atomic burn-log replay protection.
- [Capability grants and revocation](grants.md) - Default-deny capability grammar, RFC 8785 JCS signing, recursive delegation checks, and monotonic revocation lists.
- [Sans-I/O core state machines and path policy](sans-io-core.md) - Virtual-clock drivers for pairing, peer rosters, sealed sessions, and Happy Eyeballs path selection.
- [Stateless relay v1 and async runtime providers](relay-and-runtime.md) - WebSocket ciphertext relay challenge-response protocol, `local`/`direct`/`relay` transports, 6-point provider contract, rate limits, and `0700`/`0600` state persistence.
- [Six-rung path providers and relay ladder](providers-and-relay-ladder.md) - Full six-rung `ProviderId` implementations, zero-setup `iroh` P2P (`p2p-iroh`), scoped overlay helper IPC, embedded relays, and zero-re-pair `relay_hints` migration.
- [Optional push wake providers](wake-providers.md) - Pull-first opaque wake hints using hourly HKDF `WakeTag` rotation, UnifiedPush/APNs/FCM/webhook adapters, SSRF-safe delivery, and per-target coalescing.
- [Wire v2 privacy profile and PAKE](wire-v2-privacy.md) - Wire `0x02` anti-downgrade floor, pseudonymous paired reconnect, opt-in `Argon2id` PAKE pairing, blinded `/v2/relay` mailboxes, bucketed inner padding, and jittered keepalive/rekey scheduling.

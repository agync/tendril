# Design

Normative protocol design covering framing, pairing, key rotation, and capability authorization.

- [Wire protocol and pairing](wire-and-pairing.md) - Preamble framing, Noise XXhfs hybrid PQ handshake, transcript-bound pairing proof, signed multi-route pairing URIs (`rp`, `rq`, `rs`), hybrid key rotation chains, and inner encrypted transport frames including signed `0x0C` route announcements.
- [Machine-to-machine enrollment](m2m-enrollment.md) - Opt-in headless enrollment using signed single-use tokens, hybrid Ed25519 + ML-DSA-65 transcript proofs, external trust anchors, and atomic burn-log replay protection.
- [Capability grants and revocation](grants.md) - Default-deny capability grammar, RFC 8785 JCS signing, recursive delegation checks, and monotonic revocation lists.
- [Small peer mesh groups](groups.md) - Signed membership manifest for up to 32 devices, first-contact pin, revocation with rendezvous-key rotation, lazy pairwise `GroupPool` and `GroupHub` runtime, bounds, and known limits.
- [Sans-I/O core state machines and path policy](sans-io-core.md) - Virtual-clock drivers for pairing, peer rosters, sealed sessions, and Happy Eyeballs path selection.
- [Stateless relay v1 and async runtime providers](relay-and-runtime.md) - WebSocket ciphertext relay challenge-response protocol, managed relay admission (Tiers 1-3 and `--auth-scope`), `local`/`direct`/`relay` transports, 6-point provider contract, rate limits, and `0700`/`0600` state persistence.
- [Six-rung path providers and relay ladder](providers-and-relay-ladder.md) - Full six-rung `ProviderId` implementations, zero-setup and managed `iroh` P2P (`p2p-iroh`, `p2p-iroh-services`), scoped overlay helper IPC, embedded relays, legacy `relay_hints` migration (display data, never auto-dialed), and route-driven dialing (egress policy, credential origins, hint dialers).
- [Optional push wake providers](wake-providers.md) - Pull-first opaque wake hints using hourly HKDF `WakeTag` rotation, UnifiedPush/APNs/FCM/webhook adapters, SSRF-safe delivery, and per-target coalescing.
- [Wire v2 privacy profile and PAKE](wire-v2-privacy.md) - Wire `0x02` anti-downgrade floor, pseudonymous paired reconnect, opt-in `Argon2id` PAKE pairing, blinded `/v2/relay` mailboxes, bucketed inner padding, and jittered keepalive/rekey scheduling.
- [Apple platform custody and background lifecycle](apple-platform.md) - Tier 1 SEP P-256 key wrapping, Tier 2 SEP ML-DSA-65 C ABI custody, App Group Keychain/Class C isolation, `0xdead10cc` expiring-activity guards, `.extension` client-only profile, and iOS background coordinators.

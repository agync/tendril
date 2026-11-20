# Design

Normative protocol design covering framing, pairing, key rotation, and capability authorization.

- [Wire protocol and pairing](wire-and-pairing.md) - Preamble framing, Noise XX handshake, transcript-bound pairing proof, key rotation chains, and inner encrypted transport frames.
- [Capability grants and revocation](grants.md) - Default-deny capability grammar, RFC 8785 JCS signing, recursive delegation checks, and monotonic revocation lists.
- [Sans-I/O core state machines and path policy](sans-io-core.md) - Virtual-clock drivers for pairing, peer rosters, sealed sessions, and Happy Eyeballs path selection.

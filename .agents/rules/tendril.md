# Project rules: Tendril

These rules extend `AGENTS.md`.

## Security and architecture

1. **Core is the sole trust boundary.** Every path provider is untrusted by construction and may drop, delay, reorder, duplicate, inject, or lie about liveness. No provider may decrypt, forge, or widen a grant.
2. **One core, thin bindings.** Host-language bindings translate types and errors only. They must not reimplement the wire protocol, pairing checks, roster state, or grant evaluation, and must not add language-specific policy checks.
3. **Default-deny grants.** Pairing pins identity (`pair.confirm`); authority is granted separately (`pair.mint`). Every capability check fails closed on unknown, expired, or revoked grants, and delegated grants must be strict subsets.
4. **Vectors and conformance first.** Any change to the wire, pairing proof, rotation chain, or grant format updates `spec/` and `spec/vectors/` in the same change and must pass across all supported bindings.
5. **No hand-rolled cryptography and no unsafe core.** Core crates forbid `unsafe` (`unsafe_code = "forbid"`) and reuse audited cryptographic primitives. Dedicated FFI crates may isolate minimal, documented `unsafe` at the C ABI boundary only.
6. **Hermetic tests.** Tests run in-process, over in-memory pipes, or on ephemeral loopback ports using temporary directories inside `target/tmp` or test-owned temp paths. Tests never touch user keystores, home directories, or live public networks by default.

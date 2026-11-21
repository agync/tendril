# Tendril Specifications

Normative wire, pairing, capability grant, and conformance specifications for Tendril v1.

## Documents

- [wire-v1.md](wire-v1.md): 6-byte `"TND"` preamble, `uint16_be` framing (`<= 65519`), `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, hybrid key rotation chains, and inner encrypted transport frames.
- [pairing-v1.md](pairing-v1.md): hybrid identity keys, fingerprints, post-`msg2` transcript SAS, `argon2id` channel-binding `code_mac`, pairing lifecycle, `tendril://pair` URI format (`sh=` hash pin), and M2M enrollment.
- [grants-v1.md](grants-v1.md): capability grammar, RFC 8785 JCS canonical signing, recursive delegation subset checks, signed revocation lists, and fail-closed evaluation.
- [relay-v1.md](relay-v1.md): stateless WebSocket ciphertext forwarding protocol, Ed25519 challenge-response mailbox registration and accept proofs, frame limits, and abuse bounds.
- [conformance.md](conformance.md): vector, cross-language transcript, and fault-injection conformance contract.
- [vectors/README.md](vectors/README.md): canonical test vectors and independent Go verification suite.

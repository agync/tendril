# Tendril Specifications

Normative wire, pairing, capability grant, relay, and conformance specifications for Tendril v1 and v2.

## Documents

- [wire-v1.md](wire-v1.md): 6-byte `"TND"` preamble, `uint16_be` framing (`<= 65519`), `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, hybrid key rotation chains, and inner encrypted transport frames including the `0x0C` signed route set.
- [wire-v2.md](wire-v2.md): Wire v2 (`0x02`) privacy profile, `min_wire_version` anti-downgrade floor, pseudonymous paired reconnect, opt-in `FLAG_PAKE_PAIR` pairing (`Argon2id` + `Noise_XXhfs`), bucketed `0x09 PADDED`/`0x08 PADDING` inner frames, and jittered keepalive/rekey scheduling.
- [pairing-v1.md](pairing-v1.md): hybrid identity keys, fingerprints, post-`msg2` transcript SAS, `argon2id` channel-binding `code_mac`, pairing lifecycle, `tendril://pair` URI format (`sh=` hash pin, `rp`, signed `rq`/`rs` route statements), multi-route pairing rules, route provenance and announcements, and M2M enrollment.
- [grants-v1.md](grants-v1.md): capability grammar, RFC 8785 JCS canonical signing, recursive delegation subset checks, signed revocation lists, and fail-closed evaluation.
- [relay-v1.md](relay-v1.md): stateless WebSocket ciphertext forwarding protocol, Ed25519 challenge-response mailbox registration and accept proofs, frame limits, and abuse bounds.
- [relay-v2.md](relay-v2.md): stateless WSS `/v2/relay` protocol with hourly HKDF-derived Ed25519 `mailbox_id` rotation, `VerifiedRelayHost` binding, `conn_id`-bound `dial_token` verification, and separate control sockets per epoch window.
- [groups-v1.md](groups-v1.md): small peer mesh groups (up to 32 devices) with hybrid-signed `GroupManifest`, co-admin `admin_grant`, group-scoped capabilities, `0x0A`/`0x0B` frames, rendezvous bootstrap derivations, and `SessionHello.groups` gossip.
- [conformance.md](conformance.md): vector, cross-language transcript, and fault-injection conformance contract.
- [vectors/README.md](vectors/README.md): canonical test vectors and independent Go verification suite.

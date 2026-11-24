# Conformance Vectors

Canonical byte-for-byte test vectors for identity fingerprints, pairing MACs,
signed key rotations, RFC 8785 JCS capability grants, revocation lists, signed
pairing route statements and route sets, and Noise_XXhfs (hybrid X25519 +
ML-KEM-768) handshake transcripts.

## Files

- `fingerprints.json`: `device_id`, `host_fingerprint`, `device_fingerprint`, and `pairing_sas`
- `pairing_mac.json`: 3-group and 2-group normalized codes, `argon2id` keys, `code_mac`, and the human signing key claim (`key_proof`)
- `rotation.json`: hybrid-signed `RotationRecord` links (`seq = 1`, `seq = 2`, 4031-byte signed payloads) and fork rejection vector
- `grants.json`: JCS canonical grant signing (hybrid Ed25519 + ML-DSA-65), valid delegation, invalid widened delegation, and `RevocationList`
- `handshake.json`: full deterministic `pair` and `session` `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` transcripts including `0x04 REKEY`
- `m2m_enrollment.json`: signed M2M `pair.enroll` token, 3373-byte hybrid `enroll_proof`, `PairClaim`, and replay rejection vectors
- `wire_v2.json`: Wire v2 preambles, blinded `/v2/relay` hourly epoch tokens, Tier 2 HMAC & Tier 3 Ed25519 JCS `RelayTicket` admission, pseudonymous v2 reconnect (`0x09 PADDED` / `0x08 PADDING`), and hybrid `Argon2id` PAKE + `ML-KEM-768` pairing vectors
- `groups.json`: deterministic `group_id`, hybrid-signed `GroupManifest` chain (root-signed and co-admin-signed with `admin_grant`), rejection cases, `pair_bootstrap` / `group_mailbox` HKDF outputs, the `0x0B` frame, and `SessionHello.groups`
- `routes.json`: the `0x0C ROUTE_SET` codec (`spec/wire-v1.md` Section 5.2) under the top-level key `route_set`, plus `session_hello_route_seq`. `route_set` holds the fixed host key material (`static_scalar_hex`, `static_pub_hex`, `signing_seed_hex`, `signing_mldsa_seed_hex`, `signing_pub_hex`, `sh_hex`) and `domain_hex` (`"tendril-route-set-v1\0"`); `sign_deterministic`, a list of deterministically signed sets, each with `name`, `seq`, `issued_at`, `routes`, `body_hex`, `signed_bytes_hex` (the domain plus the body) and `sig_hex` (the 3,373-byte hybrid signature), where the wire payload is reconstructed as `body_hex` followed by `sig_hex`; and `decode_rejections`, a list of structurally invalid payloads (`name`, `body_hex`, `zero_filler_len`) that decoders must reject. `session_hello_route_seq` gives the `SessionHello` JSON (`json`) carrying `route_seq` (`route_seq`). The pairing URI route statement (`spec/pairing-v1.md` Section 6.5: the exact `rs_input` bytes and the Ed25519 `rs` signature for a fixed URI) is carried under the top-level key `pairing_route_statement` (`uri`, `uri_bytes_before_rs`, `hints`, `route_seq`, `domain_hex`, `rs_input_hex`, `ed25519_pub_hex`, `rs_hex`).
- `verify_go/`: independent Go test suite reproducing every vector byte-for-byte (`crypto/mlkem` + `circl/mldsa65`)

## Commands

```bash
cargo run -p tendril-core --example gen_vectors   # regenerate canonical vectors
cargo run -p tendril-core --example gen_group_vectors   # regenerate groups.json
make vectors/check                                # verify Rust and Go suites
```

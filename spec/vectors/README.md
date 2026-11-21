# Conformance Vectors

Canonical byte-for-byte test vectors for identity fingerprints, pairing MACs,
signed key rotations, RFC 8785 JCS capability grants, revocation lists, and
Noise_XXhfs (hybrid X25519 + ML-KEM-768) handshake transcripts.

## Files

- `fingerprints.json`: `device_id`, `host_fingerprint`, `device_fingerprint`, and `pairing_sas`
- `pairing_mac.json`: 3-group and 2-group normalized codes, `argon2id` keys, and `code_mac`
- `rotation.json`: hybrid-signed `RotationRecord` links (`seq = 1`, `seq = 2`, 4031-byte signed payloads) and fork rejection vector
- `grants.json`: JCS canonical grant signing (hybrid Ed25519 + ML-DSA-65), valid delegation, invalid widened delegation, and `RevocationList`
- `handshake.json`: full deterministic `pair` and `session` `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` transcripts including `0x04 REKEY`
- `m2m_enrollment.json`: signed M2M `pair.enroll` token, 3373-byte hybrid `enroll_proof`, `PairClaim`, and replay rejection vectors
- `verify_go/`: independent Go test suite reproducing every vector byte-for-byte (`crypto/mlkem` + `circl/mldsa65`)

## Commands

```bash
cargo run -p tendril-core --example gen_vectors   # regenerate canonical vectors
make vectors/check                                # verify Rust and Go suites
```

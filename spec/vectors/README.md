# Conformance Vectors

Canonical byte-for-byte test vectors for identity fingerprints, pairing MACs,
signed key rotations, RFC 8785 JCS capability grants, revocation lists, and
Noise XX handshake transcripts.

## Files

- `fingerprints.json`: `device_id`, `host_fingerprint`, `device_fingerprint`, and `pairing_sas`
- `pairing_mac.json`: 3-group and 2-group normalized codes, `argon2id` keys, and `code_mac`
- `rotation.json`: signed `RotationRecord` links (`seq = 1`, `seq = 2`) and fork rejection vector
- `grants.json`: JCS canonical grant signing, valid delegation, invalid widened delegation, and `RevocationList`
- `handshake.json`: full deterministic `pair` and `session` Noise XX transcripts including `0x04 REKEY`
- `verify_go/`: independent Go test suite reproducing every vector byte-for-byte

## Commands

```bash
cargo run -p tendril-core --example gen_vectors   # regenerate canonical vectors
make vectors/check                                # verify Rust and Go suites
```

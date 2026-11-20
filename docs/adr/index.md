# Decisions

Architecture decision records, one decision per page.

- [0001 One core, hostile paths](0001-one-core-hostile-paths.md) - Single Rust core with thin bindings, untrusted path providers, and separated pairing confirmation and capability grants.
- [0002 V1 protocol profile and Sans-I/O core](0002-v1-protocol-profile-and-sans-io-core.md) - Frozen Tendril v1 wire domain separators, transcript-bound pairing proof and SAS, humane retry limits, Sans-I/O core split, and minimal stateless WSS relay protocol.

---
type: Design
title: Sans-I/O core state machines and path policy
description: Pure Sans-I/O design for PairingInitiator, PairingResponder, Roster, SessionMachine, and PathPlanner in tendril-core.
status: stable
tags: [design, core, sans-io, policy]
---

# Sans-I/O core state machines and path policy

`tendril-core` implements pairing, session establishment, roster state, capability enforcement, and connection path selection with `#![forbid(unsafe_code)]`, explicit virtual clocks (`now_unix`, `now_ms`), and zero async or OS I/O dependencies.

## Driver loop

Callers pump raw bytes and explicit timestamps into the state machines and drain typed action slices:

```text
bytes / commands + (now_unix, now_ms) ---> StateMachine ---> Vec<Action>
```

- `ResumableFrameReader` bounds buffered bytes at `MAX_READ_BUFFER_LEN`, decodes the 6-byte cleartext preamble first, and rejects declared outer frame lengths above `65519` before payload allocation.
- Private key scalars (`StaticKeypair`, `SigningKeypair`), pairing codes, Argon2id outputs, `snow` Noise DH/cipher/hash resolvers, and decoded handshake/transport plaintext buffers use `zeroize` wrappers and redact secrets from `Debug` output.

## Pairing and roster trust transitions

| Component | Key Rules |
|---|---|
| `PairingManager` | Unbiased 31-char code sampling, `900 s` default TTL, `5` failed claims burn all live codes, single-use burn even when a `revoked` peer claims a live code, 2-group LAN codes rejected on `Remote` paths |
| `PairingUri` | `tendril://pair?v=1&...` codec validating scheme, version, non-zero static and signing keys, strict query parameters, control-character absence, and validated endpoint hints |
| `PairingInitiator` / `PairingResponder` | Decouples `pair` (`pending`) from host `confirm_peer` and `mint_grant`; validates optional QR pins before emitting `msg3` |
| `Roster` | Indexes peer entries cleanly, matches inbound `Session` peers strictly on full 32-byte `static_pub`, enforces non-zero pins (`IncompletePin`), transitions immediately to `revoked` on trust-root rotation forks, and ingests monotonic signed CRLs |

## Sealed session and path planner

- **`SessionMachine`:** Drives `Noise_XX_25519_ChaChaPoly_SHA256`, executes the initiator `msg2` pin/rotation abort gate before disclosing client static keys in `msg3`, enforces grants via `authorize_grant` returning structured `AuditEvent` records, and automatically triggers `0x04 REKEY` at `1_048_576` sent frames or `15` minutes while re-validating grants and CRLs on `REKEY` and `0x03 REVOCATION`.
- **`PathPlanner`:** Orders candidates strictly by `(provider.rank(), !is_numeric_host, id)` across `local < direct < overlay < p2p < relay < broker`, staggers Happy Eyeballs probes every `250 ms`, delays cold `p2p` probing (`500 ms`) so higher rungs race unblocked, holds pinned paths for `10 s` before probing fall-up every `30 s`, and fails over immediately on active path faults.

## Adversarial verification

In-process integration tests in `crates/tendril-core/tests/adversarial.rs` drive complete pair, confirm, mint, delegate, data, `PING`/`PONG`, frame-count and time-based auto-`REKEY`, key rotation, CRL revocation, and graceful `CLOSE` flows under 1-byte/odd-chunked I/O, frame drops/reordering/replay, bit-flips, oversized frames, cross-intent splicing, MITM handshake splicing, expired/burned pairing codes, incomplete pins, widened delegations, forged issuers, and trust-root vs. unanchored rotation forks.

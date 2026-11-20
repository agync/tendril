# Audit Lanes and Threat Surfaces

Partition the repository by trust boundary so parallel lanes never duplicate raw hunts blindly and never contend on compiled targets.

## Default Wave-1 lane map

| Lane | Focus Title | Owned Repository Paths | Key Trust Boundary Questions |
|---|---|---|---|
| `core` | Core Crypto and Grants | `spec/*.md`, `crates/tendril-core/**` | Does Noise XX prologue/transcript binding hold across intents? Are Curve25519 low-order/non-contributory DH points rejected? Do Argon2id `code_mac`, SAS binding, LAN vs Remote code rules, rotation chain/fork checks, canonical JSON (`JCS`), capability subsets, CRL rollback, nonce ceilings, and `Zeroizing` hold without panic or bypass? |
| `runtime` | Runtime, Relay, P2P and CLI | `crates/tendril-runtime/**`, `crates/tendril-relay/**`, `crates/tendril-cli/**` | Can untrusted relays, brokers, overlay sockets, or QUIC peers starve `PreAuthRateLimiter`, `InboundRouter`, or `P2pListener`? Are relay challenge proofs and URL/TLS checks strict? Do `OverlayHelper` / `LocalListener` sockets and `StateStore` handle permissions, atomic writes, symlinks, and concurrent CLI updates safely? Do active sessions enforce live revocations? |
| `bindings` | FFI, Native and Mobile Bindings | `crates/tendril-ffi/**`, `bindings/go/**`, `bindings/python/**`, `bindings/node/**`, `bindings/kotlin/**`, `bindings/swift/**` | Are raw C pointers, slices, UTF-8/UTF-16/NUL boundaries, mutex locks, GIL/event-loop lifecycles, and integer conversions (`ToUint32`, `NaN`, overflow) memory-safe and parity-preserving? Does FFI `verify_grant_json` validate CRLs? Does `pair_accept` enforce `PairingPathKind`? Are mobile Keystore/Keychain stores actually wired into endpoint persistence and backups disabled? |
| `web-privacy` | WASM, Web and Cross-Cutting Privacy | `crates/tendril-wasm/**`, `bindings/web/**`, plus cross-cutting metadata across `spec/`, `crates/`, `docs/` | Are `wasm-bindgen` lifetimes, async framing queues (`RelayStream`, `IrohStream`), `TendrilWebSession` send ordering, Worker bounds, `demo/server.mjs` headers/compression/proxy rules, `demo/app.js` DOM/URL/storage flows sound? What network, DNS, relay, LAN, and forensic metadata leaks across all layers? |

## Cross-cutting privacy adversary classes

The `web-privacy` lane (or a dedicated `privacy` lane if added later) must evaluate all six adversary perspectives:

1. **Passive internet eavesdropper:** Cleartext preambles, outer frame lengths/cadence, unencrypted fallback schemes (`ws://`, `http://`, `broker+ws://`), DNS lookups.
2. **Public discovery / relay infrastructure (such as `n0` DNS, Pkarr, public relays):** Persistent deterministic `EndpointId` correlation, source IP visibility, uptime/region presence, leakage of self-hosted custom relay URLs.
3. **Self-hosted relay or broker operator:** Unblinded `signing_pub` mailbox keys, social graph correlation, connection timestamps, unpadded message sizes.
4. **Same-LAN / active network prober:** Unauthenticated `msg1` probes eliciting `msg2` `HostHello` (`host_id`, static keys, timestamped rotation chains), socket `?addr=` leaks in URIs/QR codes.
5. **Paired or revoked peer:** Ongoing presence polling via deterministic peer IDs, stale session continuation after revocation, sibling key/CRL bypasses.
6. **Local disk / OS / browser forensic observer:** Plaintext `identity.json` and `roster.json`, unencrypted mobile backups, `localStorage` key storage, `/proc/<pid>/cmdline` `--code` exposure, unzeroized crypto buffers, stdout daemon logging.

## Extending lanes for new subsystems

When adding new protocols or crates (for example Phase 6 M2M enrollment or new path providers):
- Assign the new spec section (`spec/*.md`) and core parser/verifier to `core`.
- Assign daemon/CLI/transport wiring to `runtime`.
- Assign FFI/language wrapper methods to `bindings`.
- Add any browser/metadata impact to `web-privacy`, or add a 5th lane via `--lanes "core runtime bindings web-privacy m2m"` in `scripts/audit-worktrees.sh`.

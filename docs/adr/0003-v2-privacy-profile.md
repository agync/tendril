---
type: Decision
title: "0003 V2 privacy profile"
description: Tendril v2 privacy profile targeting relay mailbox linkability, unencrypted HostHello metadata leakage, packet-size correlation, and traffic timing fingerprinting.
status: stable
tags: [adr, privacy, relay, wire]
---

# 0003 V2 privacy profile

> **Status: Accepted.** Implemented in `spec/wire-v2.md`, `spec/relay-v2.md`, and [Wire v2 privacy profile and PAKE](../design/wire-v2-privacy.md).

## Context

Tendril v1 prioritizes cryptographic authenticity, simple stateless relaying, and cross-platform determinism over strong traffic-analysis resistance. A security and privacy audit of the v1 protocol recorded four structural metadata channels inherent to the v1 wire and relay design:

1. **Long-lived relay mailbox linkability:** `relay-v1` registers mailboxes under each endpoint's static `device_id` (`H(static_pub)`), enabling a relay operator to correlate a device's persistent pseudonymous identifier across sessions and IP changes.
2. **Passive metadata visibility before full responder authentication:** Under `Noise_XXhfs`, `HostHello` (including `host_id`, hybrid `signing_pub`, and `rotation` records) travels encrypted only against the responder's ephemeral DH and KEM (`ee` + `ekem1`) before the initiator reveals `s`; additionally, active probers who initiate handshakes can observe responder identity traits unless responders restrict or blind early responses.
3. **Plaintext length side channels:** Outer Noise frames wrap compact UTF-8 JSON payloads and inner frames without bucketed padding, leaking message type boundaries and payload size distributions to passive observers and relays.
4. **Deterministic keepalive and rekey cadence:** Fixed PING intervals and deterministic `REKEY` thresholds expose predictable timing signatures over long-lived flows.

## Decision

Keep Tendril v1 frozen for Wire Compatibility (`WIRE_VERSION = 0x01`) while defining four coordinated privacy mechanisms for the **Tendril v2 Privacy Profile** (`WIRE_VERSION = 0x02`, targeted for Phase 7+):

1. **Blinded epoch relay mailbox tokens:** Replace static `device_id` relay registrations with rotating, time-bucketed mailbox tags derived via `HKDF-SHA256` from a shared peer-pair secret or host mailbox capability and the current epoch index, preventing relay operators from linking sessions across epochs or correlating third-party dialers.
2. **Pre-authenticated or pseudonymous `HostHello`:** For already-paired peers connecting with a pre-shared key (`Noise_IK` or PSK-augmented prologue mode), hide static identity disclosure and omit static `host_id` strings from handshake metadata against unauthenticated active scanners.
3. **Bucketed inner frame padding:** Add a length-hiding padding field or dedicated padding scheme inside decrypted inner transport frames, rounding serialized frame sizes up to power-of-two or fixed size buckets (capped cleanly below `MAX_TRANSPORT_PLAINTEXT`).
4. **Jittered keepalive and rekey scheduling:** Apply bounded cryptographic PRNG jitter to background liveness pings and frame/age `0x04 REKEY` triggers so idle and low-rate flows do not emit periodic beacons.

## Consequences

- **No v1 wire break:** Existing v1 clients, CLI commands, FFI consumers, and `spec/vectors/*.json` remain untouched until v2 negotiation (`0x02` preamble) is introduced.
- **Explicit operator logging discipline in v1:** Until v2 lands, operators running `tendril serve` in multi-tenant environments should enable `--redact-logs` to mask `pairing_code`, application payload `utf8`, and `token_nonce` from JSON event stdout logs.
- **Relay protocol evolution:** v2 requires extending `tendril-relay` challenge-response authentication from static key possession (`device_id`) to epoch-blinded capability proofs without requiring persistent relay storage.

---
type: Log Entry
title: "Harden core protocol, client pairing, router, and live revocation (Audit Batch 1)"
description: "Harden core protocol, client pairing, router, and live revocation (Audit Batch 1)"
tags: [log, update]
kind: Update
status: stable
---

Harden core protocol, client pairing, router, and live revocation (Audit Batch 1).

- Core protocol (`tendril-core`, `spec/`): enforce RFC 7748 contributory DH and Ed25519 key checks, CRL signature verification and issuer/root pinning, pre-rekey plaintext encoding, pairing URI host pin and rotation continuity checks, cross-sibling revocation, and strict `deny_unknown_fields` wire/grant parsing.
- Client pairing (`tendril-core`, `tendril-ffi`, `tendril-wasm`, `tendril-cli`, Go, Python, Node, Kotlin, Swift, Web): record unpinned manual host keys as `Pending` until explicit `confirm_peer` SAS approval and reject non-matching host-pin overwrites.
- Runtime and live revocation (`tendril-runtime`, `tendril-cli`): isolate `InboundRouter` `Pair` and `Session` queues with TTL expiration and separate rate limiters, serialize state updates with `.roster.lock`, persist peer revocations and CRLs from live sessions, and refresh `Roster` state across active sessions.

---
type: Log Entry
title: "Add M2M SDK parity and transport hardening"
description: "Expose M2M enrollment APIs across Go, Python, Node, Web/WASM, Kotlin, and Swift bindings alongside pairing, WebSocket, overlay, and worker hardening."
tags: [log, update]
kind: Update
status: stable
---

# Add M2M SDK parity and transport hardening

- **Cross-language M2M SDK parity:** Exposed `addTrustAnchor` / `add_trust_anchor`, `revokeTrustAnchor` / `revoke_trust_anchor`, `mintEnrollmentToken` / `mint_enrollment_token`, and `enrollInitiate` / `enroll` across Go (`bindings/go`), Python (`bindings/python`), Node.js (`bindings/node`), Web/WASM (`crates/tendril-wasm`, `@tendril/web`), Android Kotlin JNI (`bindings/kotlin`), Apple Swift (`bindings/swift`), and `tendril-conformance-peer`, verified against live replay and anchor-revocation tests. Updated [FFI ABI and cross-language bindings](../../reference/ffi-and-bindings.md), [Web and mobile bindings](../../reference/web-and-mobile.md), and [Machine-to-machine enrollment](../../design/m2m-enrollment.md).
- **Protocol, transport, and secret-handling hardening:** Normalized pairing-claim rejection with a dummy Argon2id verification pass and uniform `"unauthorized"` wire errors (`spec/pairing-v1.md`, `spec/wire-v1.md`), rejected zero-byte WebSocket binary frames in `tendril-relay` and `tendril-runtime`, enforced Tailscale tailnet IP validation by default in `OverlayListener` with an explicit `--overlay-allow-non-tailnet` opt-in (`OverlayHelperListener` bounded via semaphore), redacted secret header values in `BrokerDialer`'s `Debug` output, added explicit connect timeouts in `DirectDialer` and `OverlayDialer`, zeroized serialized `StateStore` JSON buffers, and added zeroizing `computeCodeMacBytes` plus `timeoutMs` and `messageerror` termination handling in `computeCodeMacWorker`. Documented CLI behavior in [Reference CLI, relay deployment, and conformance peer](../../usage/cli-demo.md).

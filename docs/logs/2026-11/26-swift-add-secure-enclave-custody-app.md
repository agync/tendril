---
type: Log Entry
title: "swift: add Secure Enclave custody and background APIs"
description: "Add Secure Enclave custody, App Group hardening, and background coordinators."
tags: [log, update]
kind: Update
status: stable
---

swift: add Secure Enclave custody and background APIs

Add Tier 1 Secure Enclave P-256 ECIES state wrapping (`0x02`) with anti-downgrade and `0x01 -> 0x02` migration alongside Tier 2 `SecureEnclave.MLDSA65` signing custody (`TendrilMlDsa65Provider` / `CTendrilMlDsa65Bridge`) gated under `#if compiler(>=6.2)` and OS 26 availability checks. Harden `SealedSwiftStateStore` and `TendrilKeychainStore` for App Groups (`kSecAttrAccessGroup`, conditional macOS `kSecUseDataProtectionKeychain`, Class C `FileProtectionType.completeUntilFirstUserAuthentication`), add `TendrilExpiringActivityState` (`performExpiringActivity`) and `TendrilEndpointOptions.extensionClientOnly` (`runtime_profile: "extension"`, `client_only: true`), and implement `TendrilWakeProcessor`, `TendrilLocalPushSession`, and `TendrilBackgroundSync` in `AppleBackground.swift` with unit tests in `AppleCustodyAndBackgroundTests.swift` and design docs in [Apple platform custody and background lifecycle](../../design/apple-platform.md).

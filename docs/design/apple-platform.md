---
type: Design
title: Apple platform custody and background lifecycle
description: Tier 1 Secure Enclave P-256 ECIES key-wrapping, Tier 2 ML-DSA-65 hardware signing, App Group Keychain and Class C hardening, 0xdead10cc expiring-activity protection, and iOS background coordinators.
status: stable
tags: [design, apple, swift, security, wake, extensions]
---

# Apple platform custody and background lifecycle

Tendril keeps `tendril-core` as the sole cryptographic and protocol trust boundary while adapting Swift state storage, key custody, and process lifecycle in `bindings/swift` for iOS, macOS, tvOS, watchOS, and visionOS apps and extensions.

See [ADR 0005](../adr/0005-apple-custody-wake-and-extensions.md) for the architectural decision record and [Optional push wake providers](wake-providers.md) for wire wake-tag derivation.

## Two-tier Secure Enclave custody

Swift separates storage sealing (Tier 1) from post-quantum identity signing (Tier 2) so current Apple OS releases gain non-extractable hardware wrapping immediately while Apple Silicon OS 26+ hardware binds ML-DSA-65 signing keys directly in Secure Enclave.

| Layer | Availability | Primitive and storage | Fail-closed rule |
|---|---|---|---|
| Legacy storage envelope (`0x01`) | iOS 16+, macOS 13+ | 32-byte `kSecClassGenericPassword`, AES-GCM (`tendril.state.v1\0`) | Rejected once v2 custody commits (`v2CustodyCommitted` or `.sep-v2-committed` marker) or `.secureEnclaveRequired` is set; `.sep-v2-committed` read errors fail closed |
| Tier 1 SEP key wrap (`0x02`) | iOS 16+, macOS 13+ | `SecureEnclave.P256.KeyAgreement` ephemeral ECDH + HKDF-SHA256 (`tendril.se.wrap.v1`) + AES-GCM (`tendril.state.v2\0`), `.sep-p256` handle | Two-phase commit (`beginUpgradeV1ToV2`, atomic disk write + `F_FULLFSYNC`/`fsync` directory sync, then `commitV2Custody` writing `.sep-v2-committed`, deferred unconditionally during `openSealed` until runtime sync completes); standalone `sealState` deletes brand-new `.sep-p256` on wrap failure and writes `.sep-v2-committed` on success; `openState` on `0x02` records `.sep-v2-committed` (`openStateWithoutCommit` defers during bootstrap); fallback excludes `CryptoKitError`, `errSecInteractionNotAllowed`, and `errSecWrPerm` |
| Tier 2 SEP PQ signing | OS 26+, Swift 6.2+ (`#if compiler(>=6.2)`) | `SecureEnclave.MLDSA65.PrivateKey` (`.sep-mldsa65`, 1952 B pubkey, 3309 B sig) via `TendrilMlDsa65Signer` | Opt-in on creation (`useHardwareMlDsaIfAvailable`, default `false`); existing `version == 2` reopens propagate keychain/CryptoKit errors without `try?` suppression and fail closed on mismatch |

### Storage envelope formats (`TendrilKeychainStore`)

`TendrilKeychainStore` derives its access policy from `TendrilKeychainConfiguration` (`service`, `account`, `accessGroup`, `custody`, `accessControlFlags`). Access control defaults strictly to `[.privateKeyUsage]` with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, avoiding interactive biometry prompts that fail with `errSecInteractionNotAllowed` in background extensions.

- **Version `0x01` (legacy software master key):** `0x01 || AES-GCM(plaintext, key = masterKey, aad = "tendril.state.v1\0" || aad)`
- **Version `0x02` (Tier 1 Secure Enclave ECIES):** `0x02 || ephPubX963(65B) || AES-GCM(plaintext, key = HKDF-SHA256(ecdh(sepKey, ephPub), salt = ephPubX963 || sepPubX963, info = "tendril.se.wrap.v1", len = 32), aad = "tendril.state.v2\0" || aad)`

When opening `identity.sealed` with a fresh store before v2 custody has committed, `SealedSwiftStateStore` runs a two-phase upgrade: `beginUpgradeV1ToV2` checks that v2 custody is uncommitted, decrypts `0x01`, loads or creates `.sep-p256` (reusing an uncommitted `.sep-p256` from an interrupted upgrade), and returns the `0x02` envelope and plaintext without committing `.sep-v2-committed`. `SealedSwiftStateStore` persists the `0x02` envelope via atomic `writeSealedBytes` (temp file + `synchronize()` + `replaceItemAt` + `syncDirectory()` using `F_FULLFSYNC` with `fsync` fallback), and invokes `syncDirectory()` + `commitV2Custody()` (`storeGenericData` for `.sep-v2-committed` and `v2CustodyCommitted = true`) only after disk durability holds (standalone `loadIdentityJson()` / `saveIdentityJson()` also defer commitment automatically while `legacyRosterNeedsMigration()` holds). On `openSealed`, if `identity.sealed` is present alongside `legacyRosterNeedsMigration()`, `roster.sealed` is loaded and upgraded first (`loadRosterJson(upgradeIfNeeded: true, deferCommit: true)`); if `identity.sealed` is missing (`!hasIdentityFile()`), any orphaned `roster.sealed` cannot belong to the freshly generated identity and is discarded unread without seeding. `openSealed` passes `deferCommit: true` unconditionally when reading, upgrading, or saving `identity.sealed`, initializes runtime state via `newSealedWithOptions`, unlinks any remaining `roster.sealed` via `deleteLegacyRoster()` (`syncDirectory()`), and finally runs `commitV2CustodyIfNeeded()` (`syncDirectory()` then `commitV2Custody()`) so crashes at any write, sync, or unlink step remain recoverable. Once v2 custody commits (`v2CustodyCommitted` or `.sep-v2-committed` in Keychain), `openState`, `openStateWithoutCommit`, `beginUpgradeV1ToV2`, and `sealState` reject `0x01` envelopes with `TendrilKeychainError.downgradeRejected`. Commitment checks on `.sep-v2-committed` and `.sep-p256` fail closed on read errors: `#if !os(macOS)` always rethrows Keychain read errors, while `#if os(macOS)` tolerates only `errSecMissingEntitlement` / `-34018` when `custody != .secureEnclaveRequired && accessGroup == nil`.

Standalone `sealState` cleans up a newly created `.sep-p256` item if `sealV2Envelope` or commitment marker persistence fails, and writes `.sep-v2-committed` on success. Successfully decrypting a `0x02` envelope in `openState` sets `v2CustodyCommitted = true` and persists `.sep-v2-committed` if missing.

### Tier 2 hardware ML-DSA-65 C ABI lifecycle

Because Secure Enclave hardware does not expose Ed25519 signing, Tier 2 stores only `ML-DSA-65` in SEP (`SecureEnclaveMlDsa65Provider`, opt-in on fresh identities via `TendrilEndpointOptions(useHardwareMlDsaIfAvailable: true)` which defaults to `false`), while `PersistedIdentity` `version: 2` retains the Ed25519 seed (`signing_seed_b64`) inside Tier 1 SEP-wrapped `identity.sealed` and omits `pq_signing_seed_b64`. Reopening an existing `version: 2` identity automatically attempts `SecureEnclaveMlDsa65Provider.loadExisting` when Keychain custody allows hardware ML-DSA without requiring callers to repeat `useHardwareMlDsaIfAvailable: true`. Compilation of `SecureEnclave.MLDSA65` is doubly guarded behind `#if compiler(>=6.2)` and `@available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)` so Xcode 16 (Swift 6.0/6.1) compiles cleanly.

```mermaid
sequenceDiagram
  participant Swift as "CTendrilMlDsa65Bridge"
  participant CABI as "tendril_endpoint_new_sealed_with_options"
  participant Rust as "SignerCtxGuard / Arc"

  Swift->>CABI: "passRetained(bridge) as ctx, cSign, cDropCtx"
  CABI->>Rust: "wrap non-null ctx in RAII guard on entry"
  alt "Option parse or signer check fails"
    Rust-->>Swift: "drop_ctx(ctx) invoked once, returns NULL"
  else "Endpoint live, then freed"
    Rust->>Swift: "cSign(ctx, msg, context, out_sig) on worker threads"
    Note over Rust: "TendrilGroup Pool retains Arc<EndpointIdentity>; sessions do not"
    Rust-->>Swift: "drop_ctx(ctx) invoked once on final Arc drop"
  end
```

`CTendrilMlDsa65Bridge` transfers one `+1` retained `ctx` pointer per constructor call and relies on Rust's `SignerCtxGuard` and `FfiMlDsa65Signer` to invoke `drop_ctx(ctx)` once across both failure (`NULL`) and final `Arc` release (while releasing an untransferred `ctx` in `defer` if a Swift helper throws before invoking the C constructor).

## App Group isolation and Keychain query scoping

Sharing sealed state between a host app and a Network or Notification Service Extension requires **matching** `accessGroup`, `service`, and `account` values across `TendrilKeychainConfiguration` (plus shared App Group container `stateDir`):

1. **Keychain Access Groups and macOS Data Protection Keychain:** `TendrilKeychainConfiguration.accessGroup` attaches `kSecAttrAccessGroup` to both Keychain reads and writes (`master-key-v1`, `.sep-p256`, `.sep-v2-committed`, `.sep-mldsa65`). All extension targets accessing the shared identity MUST configure the identical `accessGroup`, `service`, and `account` tuple in `TendrilKeychainConfiguration` so queries target the exact shared Keychain items. On macOS (`#if os(macOS)`), `kSecUseDataProtectionKeychain: true` is attached for SEP/v2 queries, shared `accessGroup` configurations, or `.secureEnclaveRequired`, while omitted on default unentitled macOS CLI stores.
2. **Class C file protection and backup exclusion:** `SealedSwiftStateStore` creates the App Group `stateDir` with `0o700` permissions, sets `isExcludedFromBackup = true`, and (on iOS, tvOS, watchOS, and visionOS) sets `FileProtectionType.completeUntilFirstUserAuthentication` (Class C) on the directory, on every atomic write (`writeSealedBytes`), and across all regular files inside `stateDir` at initialization and via `withBootstrapLock` completion/error cleanup. Class A (`complete`) is never used because background wakes and local push sessions must run while the device screen is locked after first unlock.

## Expiring activity and extension runtime profile

To avoid `0xdead10cc` termination when iOS suspends an app or extension holding `.identity.lock`, `.roster.lock`, or runtime sealed state files, sealed-store operations wrap execution inside `TendrilExpiringActivityState` backed by `ProcessInfo.processInfo.performExpiringActivity(withReason:using:)` (`#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)`):

- **Covered operations:** `TendrilEndpoint` initialization/bootstrap (`openSealed` + `withBootstrapLock`), `configureTransportsJSON`, `configureRoutes`, `configurePower`, `issueCode`, pairing (`pairInitiate`, `pairAccept`, `pairV2Initiate`, `pairV2Accept`, `pairUri`, `pairV2Uri`, `confirmPeer`, `mintGrant`, `revokePeer`, M2M trust/enrollment APIs), routing (`issuePairingUri`, `setPeerRoutes`, `clearPeerRoutes`, `applyRouteUri`, `refreshRoutes`), session setup/accept (`connect`, `connectWithOptions`, `connectV2`, `acceptSession`, `acceptV2`), group operations (`groupCreate`, `groupAddMember`, `groupRemoveMember`, `groupIngestManifest`, `openGroup`), plus sealed-endpoint-backed `TendrilSession` (`rekey`, `close`, plus `pollEvent` inside `.extension`) and `TendrilGroup` (`broadcast`, `sync`, plus `pollEvent` inside `.extension`) calls. Read-only getters (`infoJson`, `peerRoutes`, `peerId`, `authorize`, `localEndpoint`, `authorizePeer`) and in-memory `TendrilSession.sendData` frames run directly without acquiring expiring activity assertions, and blocking `pollEvent`/`connect*`/`accept*`/`pair*` calls only acquire `performExpiringActivity` under `.extension` profiles (`active: hasSealedStore && (!allowExpireClose || isExtensionProfile)`), avoiding foreground background-assertion churn.
- **Expired before start:** `TendrilExpiringActivityState` skips execution, invokes `onExpire` once, and throws `TendrilError.closed`.
- **Expired mid-flight:** For blocking `.extension` operations opted into expiry close (`pair*`, `connect*`, `accept*`, `enrollInitiate`, `session.pollEvent`, `group.pollEvent`), `onExpire` triggers once and dispatches `close()` / `free()` asynchronously onto `tendrilExpiringCloseQueue` so Foundation's `performExpiringActivity` callback never blocks on FFI shutdown locks.

For memory-constrained extensions (such as the ~24 MiB Notification Service Extension ceiling), `TendrilEndpointOptions.extensionClientOnly` passes `{"client_only":true,"power_profile":"low_power","runtime_profile":"extension"}` (while `TendrilEndpointOptions.lowPowerHost` selects `.lowPower` for foreground hosts) to `tendril_endpoint_new_sealed_with_options`, activating single-worker compact runtime settings, `StateStore::open_sealed_existing_fast`, `PowerProfile::LowPower`, blocking listener/hosting operations (`serveDirect`, `serveRelay`, `serveRelayV2`, `serveP2p`, `issuePairingUri`, `refreshRoutes`, `openGroup` with a non-nil `listenAddr`), and suppressing background `RouteAnnouncer` timers. Calling `startPathMonitoring()` (`NWPathMonitor`) calls `setExternalPathMonitor(true)` once started (and `false` on `stopPathMonitoring()`) so the native `60 s` route timer backs off while OS callbacks own interface changes.

## Background and push extension coordinators

All background entry points live in `bindings/swift/Sources/Tendril/AppleBackground.swift` with `Sendable` concurrency isolation and strict platform availability gates:

| Coordinator | Target Apple API | Platform gate | Trust boundary and cancellation |
|---|---|---|---|
| `TendrilWakeProcessor` | `UNNotificationServiceExtension` | `canImport(CryptoKit) && canImport(Security)` | Parses `TendrilWakePayload` (rejects `Bool`/`CFBoolean`, floats, negatives, and unaligned `epoch_s`), verifies `epoch_s` falls in the active 3600 s `+-1` bucket window, verifies `wake_tag` in constant time via `TendrilCrypto.verifyWakeTag` (`tendril_verify_wake_tag`), dials stored routes in `.extension` + `.lowPower` (`clientOnly: true`), requires a non-empty `requiredCap` and enforces `sess.authorize(requiredCap)` before delivering data, and dispatches `cancel()` session/endpoint teardown asynchronously for `serviceExtensionTimeWillExpire()` |
| `TendrilLocalPushSession` | `NEAppPushProvider` | `canImport(NetworkExtension) && (os(iOS) || os(visionOS))`, `@available(iOS 14.0, visionOS 1.0, *)` | Maintains a long-lived `connectV2` control stream over an explicit LAN relay endpoint in `.extension` + `.lowPower` (`clientOnly: true`), parks `sess.pollEvent(timeoutMs: 300_000)` (`5 min`, woken immediately on frame arrival or `sess.free()` shutdown) to avoid `1 Hz` wakeup loops, requires a non-empty `requiredCap`, enforces `sess.authorize(requiredCap)` before surfacing frames, tracks `runGeneration` across immediate `stop()`/`start()` cycles, and tears down cleanly on `stop(with:completionHandler:)` |
| `TendrilBackgroundSync` | `BGAppRefreshTask` / `BGProcessingTask` | `canImport(BackgroundTasks) && (os(iOS) || os(tvOS) || os(visionOS))`, `@available(iOS 13.0, tvOS 13.0, visionOS 1.0, *)` | Wraps `BGTask` lifecycle and `expirationHandler` around an `.extension` + `.lowPower` (`clientOnly: true`) endpoint whose caller operations enforce grants through core sessions, avoids `task` retain cycles via `[weak]` capture, invokes `task.setTaskCompleted(success: false)` first inside `task.expirationHandler`, and dispatches `endpoint.close()` asynchronously |

import CTendril
import Foundation

#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security
#endif

public protocol TendrilMlDsa65Provider: AnyObject, Sendable {
  var publicKeyData: Data { get }
  func sign(message: Data, context: Data) throws -> Data
}

public enum TendrilMlDsa65Error: Error, Equatable, Sendable {
  case invalidPublicKeyLength(Int)
  case invalidSignatureLength(Int)
  case secureEnclaveUnavailable
  case keychainStatus(Int32)
  case signingFailed(String)
}

/// Bridges a Swift `TendrilMlDsa65Provider` across the C ABI (`TendrilMlDsa65Signer`).
///
/// Ownership contract (matching `crates/tendril-ffi/include/tendril.h`):
/// - `public_key` (`1952` bytes) is copied synchronously before `tendril_endpoint_new_sealed_with_options` returns.
/// - `ctx` receives an `Unmanaged.passRetained(self)` reference immediately before calling the C constructor.
/// - Rust's `SignerCtxGuard` and `FfiMlDsa65Signer` invoke `drop_ctx(ctx)` exactly once on BOTH error (`nil` return)
///   and final internal `Arc` drop. Swift must NOT release `self` manually after the C call.
/// - `sign` and `drop_ctx` may run concurrently on arbitrary worker threads and never unwind across C ABI.
internal final class CTendrilMlDsa65Bridge: @unchecked Sendable {
  private let lock = NSLock()
  private let provider: any TendrilMlDsa65Provider
  private let onDrop: (@Sendable () -> Void)?
  private var didDrop = false
  private var transferred = false

  init(provider: any TendrilMlDsa65Provider, onDrop: (@Sendable () -> Void)? = nil) {
    self.provider = provider
    self.onDrop = onDrop
  }

  private func notifyDropped() {
    lock.lock()
    let shouldNotify = !didDrop
    didDrop = true
    lock.unlock()
    if shouldNotify {
      onDrop?()
    }
  }

  private func markTransferred() {
    lock.lock()
    transferred = true
    lock.unlock()
  }

  private static let cSign: @convention(c) (
    UnsafeMutableRawPointer?,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
  ) -> Int32 = { ctx, msgPtr, msgLen, mldsaCtxPtr, mldsaCtxLen, outSigPtr, outSigLen in
    guard let ctx, let outSigPtr else {
      return TENDRIL_ERR_INVALID_ARG.rawValue
    }
    guard outSigLen == Int(TENDRIL_MLDSA65_SIG_LEN) else {
      return TENDRIL_ERR_INVALID_ARG.rawValue
    }
    guard msgLen >= 0, mldsaCtxLen >= 0 else {
      return TENDRIL_ERR_INVALID_ARG.rawValue
    }
    if msgLen > 0 && msgPtr == nil {
      return TENDRIL_ERR_INVALID_ARG.rawValue
    }
    if mldsaCtxLen > 0 && mldsaCtxPtr == nil {
      return TENDRIL_ERR_INVALID_ARG.rawValue
    }

    let bridge = Unmanaged<CTendrilMlDsa65Bridge>.fromOpaque(ctx).takeUnretainedValue()
    let message = (msgLen > 0 && msgPtr != nil) ? Data(bytes: msgPtr!, count: msgLen) : Data()
    let context = (mldsaCtxLen > 0 && mldsaCtxPtr != nil)
      ? Data(bytes: mldsaCtxPtr!, count: mldsaCtxLen)
      : Data()

    do {
      var sig = try bridge.provider.sign(message: message, context: context)
      defer {
        if !sig.isEmpty {
          sig.resetBytes(in: 0..<sig.count)
        }
      }
      guard sig.count == Int(TENDRIL_MLDSA65_SIG_LEN) else {
        return TENDRIL_ERR_PROTOCOL.rawValue
      }
      sig.withUnsafeBytes { raw in
        if let base = raw.baseAddress {
          UnsafeMutableRawPointer(outSigPtr).copyMemory(
            from: base,
            byteCount: Int(TENDRIL_MLDSA65_SIG_LEN)
          )
        }
      }
      return TENDRIL_OK.rawValue
    } catch {
      return TENDRIL_ERR_INVALID_ARG.rawValue
    }
  }

  private static let cDropCtx: @convention(c) (UnsafeMutableRawPointer?) -> Void = { ctx in
    guard let ctx else { return }
    let bridge = Unmanaged<CTendrilMlDsa65Bridge>.fromOpaque(ctx).takeRetainedValue()
    bridge.notifyDropped()
  }

  /// Validates the 1952-byte public key, enters `withUnsafeBytes`, and passes a `+1` retained
  /// `ctx` alongside a `markTransferred` callback into `body`. Callers must invoke
  /// `markTransferred()` immediately before entering `tendril_endpoint_new_sealed_with_options`,
  /// after which Rust invokes `drop_ctx(ctx)` once on failure or final `Arc` drop even if Swift
  /// later throws. If `body` throws before calling `markTransferred()`, `defer` releases the
  /// untransferred `+1` retain cleanly.
  func withCSigner<R>(
    _ body: (UnsafePointer<TendrilMlDsa65Signer>, _ markTransferred: @Sendable () -> Void) throws -> R
  ) throws -> R {
    let pub = provider.publicKeyData
    guard pub.count == Int(TENDRIL_MLDSA65_PUB_LEN) else {
      throw TendrilMlDsa65Error.invalidPublicKeyLength(pub.count)
    }
    return try pub.withUnsafeBytes { pubRaw in
      guard let pubBase = pubRaw.bindMemory(to: UInt8.self).baseAddress else {
        throw TendrilMlDsa65Error.invalidPublicKeyLength(0)
      }
      lock.lock()
      didDrop = false
      transferred = false
      lock.unlock()
      let retainedCtx = Unmanaged.passRetained(self).toOpaque()
      var cSigner = CTendril.TendrilMlDsa65Signer(
        ctx: retainedCtx,
        public_key: pubBase,
        public_key_len: pub.count,
        sign: Self.cSign,
        drop_ctx: Self.cDropCtx
      )
      defer {
        lock.lock()
        let shouldRelease = !transferred && !didDrop
        if shouldRelease {
          didDrop = true
        }
        lock.unlock()
        if shouldRelease {
          _ = Unmanaged<CTendrilMlDsa65Bridge>.fromOpaque(retainedCtx).takeRetainedValue()
        }
      }
      return try body(&cSigner) {
        self.markTransferred()
      }
    }
  }
}

#if canImport(CryptoKit) && canImport(Security)
#if compiler(>=6.2)
@available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
public final class SecureEnclaveMlDsa65Provider: TendrilMlDsa65Provider, @unchecked Sendable {
  internal static let accountSuffix = ".sep-mldsa65"

  private let lock = NSLock()
  private let privateKey: SecureEnclave.MLDSA65.PrivateKey
  public let publicKeyData: Data
  public let configuration: TendrilKeychainConfiguration

  public init(configuration: TendrilKeychainConfiguration = TendrilKeychainConfiguration()) throws {
    guard SecureEnclave.isAvailable else {
      throw TendrilMlDsa65Error.secureEnclaveUnavailable
    }
    let key = try Self.loadOrCreateKey(configuration: configuration)
    let rawPub = key.publicKey.rawRepresentation
    guard rawPub.count == Int(TENDRIL_MLDSA65_PUB_LEN) else {
      throw TendrilMlDsa65Error.invalidPublicKeyLength(rawPub.count)
    }
    self.privateKey = key
    self.publicKeyData = rawPub
    self.configuration = configuration
  }

  private init(
    privateKey: SecureEnclave.MLDSA65.PrivateKey,
    configuration: TendrilKeychainConfiguration
  ) throws {
    let rawPub = privateKey.publicKey.rawRepresentation
    guard rawPub.count == Int(TENDRIL_MLDSA65_PUB_LEN) else {
      throw TendrilMlDsa65Error.invalidPublicKeyLength(rawPub.count)
    }
    self.privateKey = privateKey
    self.publicKeyData = rawPub
    self.configuration = configuration
  }

  internal static func loadExisting(
    configuration: TendrilKeychainConfiguration
  ) throws -> SecureEnclaveMlDsa65Provider? {
    guard SecureEnclave.isAvailable else {
      throw TendrilMlDsa65Error.secureEnclaveUnavailable
    }
    guard let blob = try TendrilKeychainStore.readGenericData(
      configuration: configuration,
      accountSuffix: accountSuffix,
      isSepOrV2: true
    ) else {
      return nil
    }
    let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: blob)
    return try SecureEnclaveMlDsa65Provider(privateKey: key, configuration: configuration)
  }

  private static func loadOrCreateKey(
    configuration: TendrilKeychainConfiguration
  ) throws -> SecureEnclave.MLDSA65.PrivateKey {
    if let existing = try TendrilKeychainStore.readGenericData(
      configuration: configuration,
      accountSuffix: accountSuffix,
      isSepOrV2: true
    ) {
      return try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: existing)
    }
    let accessControl = try TendrilKeychainStore.makeAccessControl(flags: configuration.accessControlFlags)
    let fresh = try SecureEnclave.MLDSA65.PrivateKey(accessControl: accessControl)
    if try TendrilKeychainStore.storeGenericData(
      fresh.dataRepresentation,
      configuration: configuration,
      accountSuffix: accountSuffix,
      isSepOrV2: true
    ) {
      return fresh
    }
    if let raced = try TendrilKeychainStore.readGenericData(
      configuration: configuration,
      accountSuffix: accountSuffix,
      isSepOrV2: true
    ) {
      return try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: raced)
    }
    throw TendrilMlDsa65Error.keychainStatus(errSecDuplicateItem)
  }

  public func sign(message: Data, context: Data) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    let sig = try privateKey.signature(for: message, context: context)
    guard sig.count == Int(TENDRIL_MLDSA65_SIG_LEN) else {
      throw TendrilMlDsa65Error.invalidSignatureLength(sig.count)
    }
    return sig
  }
}
#endif
#endif

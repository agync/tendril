import CTendril
import Foundation
#if canImport(Darwin)
import Darwin
#endif
#if canImport(Network)
import Network
#endif

public enum TendrilError: Error, Equatable, Sendable {
  case wouldBlock
  case eof
  case invalidArgument(String)
  case closed
  case ffi(code: Int32, message: String)
  /// The host proved it knows this device and refuses to serve it. A Wire v2 connect throws it
  /// at once. After a Wire v1 connect, and after a v2 refusal that lands once the session is
  /// up, `sendData`, `rekey` and `close` throw it and `pollEvent` delivers a `closed` event
  /// that `TendrilRefusal(closedEventJson:)` turns into the same value.
  case refused(TendrilRefusal)
}

/// Why a host refused this device. Read the app guidance on each case.
public enum TendrilRefusal: Equatable, Sendable {
  /// The host blocks this device key permanently (close code 4001, `refused_revoked`).
  /// Retrying cannot help and re-pairing needs a new device identity: offer to forget the host.
  case revoked
  /// The host has not confirmed this device yet (close code 4004, `refused_pending`). Retry with
  /// backoff.
  case pending
  /// Another refusal (`refused`), with its close code in 4400...4499. The code is 0 when the
  /// refusal came from a failed call, which reports only the reason.
  case other(UInt16)

  /// The close code of the refusal on the wire.
  public var closeCode: UInt16 {
    switch self {
    case .revoked: return UInt16(TENDRIL_CLOSE_PEER_REVOKED)
    case .pending: return UInt16(TENDRIL_CLOSE_PEER_PENDING)
    case .other(let code): return code
    }
  }

  /// The stable machine code `tendril_last_error_code` reports: `refused_revoked`,
  /// `refused_pending` or `refused`.
  public var code: String {
    switch self {
    case .revoked: return "refused_revoked"
    case .pending: return "refused_pending"
    case .other: return "refused"
    }
  }

  /// Maps a stable last-error code to a refusal, nil for any other code.
  internal init?(code: String) {
    switch code {
    case "refused_revoked": self = .revoked
    case "refused_pending": self = .pending
    case "refused": self = .other(0)
    default: return nil
    }
  }

  /// The refusal a `closed` session event carries, nil for any other event and for a close
  /// that is no refusal. Only sessions this endpoint dialed report one.
  public init?(closedEventJson json: String) {
    guard
      let any = try? JSONSerialization.jsonObject(with: Data(json.utf8)),
      let event = any as? [String: Any],
      event["event"] as? String == "closed",
      let refusal = event["refusal"] as? String
    else {
      return nil
    }
    switch refusal {
    case "revoked": self = .revoked
    case "pending": self = .pending
    case "other":
      let code = (event["code"] as? NSNumber).flatMap { UInt16(exactly: $0.intValue) } ?? 0
      self = .other(code)
    default: return nil
    }
  }
}

extension TendrilRefusal: CustomStringConvertible {
  public var description: String {
    switch self {
    case .revoked: return "refused by peer (revoked)"
    case .pending: return "refused by peer (pending)"
    case .other(let code): return "refused by peer (other, close code \(code))"
    }
  }
}

public enum TendrilRuntimeProfile: String, Sendable, Equatable {
  case `default` = "default"
  case `extension` = "extension"
}

public enum TendrilPowerProfile: String, Sendable, Equatable {
  case standard = "standard"
  case lowPower = "low_power"
}

public struct TendrilEndpointOptions: Sendable {
  public var runtimeProfile: TendrilRuntimeProfile
  public var clientOnly: Bool
  public var mldsaSigner: (any TendrilMlDsa65Provider)?
  public var useHardwareMlDsaIfAvailable: Bool
  public var powerProfile: TendrilPowerProfile?

  public init(
    runtimeProfile: TendrilRuntimeProfile = .default,
    clientOnly: Bool = false,
    mldsaSigner: (any TendrilMlDsa65Provider)? = nil,
    useHardwareMlDsaIfAvailable: Bool = false,
    powerProfile: TendrilPowerProfile? = nil
  ) {
    self.runtimeProfile = runtimeProfile
    self.clientOnly = clientOnly
    self.mldsaSigner = mldsaSigner
    self.useHardwareMlDsaIfAvailable = useHardwareMlDsaIfAvailable
    self.powerProfile = powerProfile
  }

  public static let extensionClientOnly = TendrilEndpointOptions(
    runtimeProfile: .extension,
    clientOnly: true,
    powerProfile: .lowPower
  )

  public static let lowPowerHost = TendrilEndpointOptions(
    runtimeProfile: .default,
    clientOnly: false,
    powerProfile: .lowPower
  )
}

private struct SealedEndpointOptionsPayload: Encodable {
  let runtimeProfile: String
  let clientOnly: Bool
  let powerProfile: String?

  enum CodingKeys: String, CodingKey {
    case runtimeProfile = "runtime_profile"
    case clientOnly = "client_only"
    case powerProfile = "power_profile"
  }
}

internal func encodeSealedEndpointOptionsJson(_ options: TendrilEndpointOptions) throws -> String {
  let payload = SealedEndpointOptionsPayload(
    runtimeProfile: options.runtimeProfile.rawValue,
    clientOnly: options.clientOnly,
    powerProfile: options.powerProfile?.rawValue
  )
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys]
  let data = try encoder.encode(payload)
  return String(decoding: data, as: UTF8.self)
}

internal final class TendrilExpiringActivityState<T>: @unchecked Sendable {
  private let lock = NSLock()
  private var started = false
  private var finished = false
  private var expiredBeforeStart = false
  private var result: Result<T, Error>?
  private let sem = DispatchSemaphore(value: 0)
  private let onExpire: (@Sendable () -> Void)?

  init(onExpire: (@Sendable () -> Void)? = nil) {
    self.onExpire = onExpire
  }

  func handleEvent(expired: Bool, _ body: () throws -> T) {
    if expired {
      var triggerExpire = false
      var signalNow = false
      lock.lock()
      if !finished {
        if started {
          triggerExpire = true
        } else {
          expiredBeforeStart = true
          finished = true
          result = .failure(TendrilError.closed)
          signalNow = true
        }
      }
      lock.unlock()
      if triggerExpire {
        onExpire?()
      } else if signalNow {
        onExpire?()
        sem.signal()
      }
      return
    }

    lock.lock()
    if finished || started || expiredBeforeStart {
      lock.unlock()
      return
    }
    started = true
    lock.unlock()

    let outcome = Result<T, Error>(catching: body)

    lock.lock()
    if !finished {
      result = outcome
      finished = true
      sem.signal()
    }
    lock.unlock()
  }

  func wait() throws -> T {
    sem.wait()
    lock.lock()
    let outcome = result
    lock.unlock()
    guard let outcome else {
      throw TendrilError.closed
    }
    return try outcome.get()
  }
}

private let tendrilExpiringCloseQueue = DispatchQueue(
  label: "dev.tendril.expiring-close",
  qos: .userInitiated
)

internal func withExpiringStateActivity<T>(
  reason: String = "dev.tendril.state-lock",
  onExpire: (@Sendable () -> Void)? = nil,
  _ body: @escaping @Sendable () throws -> T
) throws -> T {
  #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
  let coordinator = TendrilExpiringActivityState<T>(onExpire: onExpire)
  ProcessInfo.processInfo.performExpiringActivity(withReason: reason) { expired in
    coordinator.handleEvent(expired: expired, body)
  }
  return try coordinator.wait()
  #else
  _ = (reason, onExpire)
  return try body()
  #endif
}

internal func withExpiringActivityGuard<T>(
  active: Bool,
  allowExpireClose: Bool = false,
  onAsyncClose: (@Sendable () -> Void)? = nil,
  _ body: @escaping @Sendable () throws -> T
) throws -> T {
  guard active else {
    return try body()
  }
  let onExpire: (@Sendable () -> Void)?
  if allowExpireClose, let onAsyncClose {
    onExpire = {
      tendrilExpiringCloseQueue.async(execute: onAsyncClose)
    }
  } else {
    onExpire = nil
  }
  return try withExpiringStateActivity(onExpire: onExpire, body)
}

/// Copies the last FFI error text, or its stable code when `code` is true. The error state is
/// thread-local: read it on the thread of the failing FFI call, before any other call.
private func readLastFfi(code: Bool) -> String {
  func read(_ ptr: UnsafeMutableBufferPointer<CChar>) -> Int {
    Int(code ? tendril_last_error_code(ptr.baseAddress, ptr.count) : tendril_last_error(ptr.baseAddress, ptr.count))
  }
  var buf = [CChar](repeating: 0, count: 512)
  let needed = buf.withUnsafeMutableBufferPointer { read($0) }
  if needed <= 1 {
    return ""
  }
  if needed <= buf.count {
    return String(cString: buf)
  }
  var larger = [CChar](repeating: 0, count: needed)
  _ = larger.withUnsafeMutableBufferPointer { read($0) }
  return String(cString: larger)
}

private func lastFfiError() -> String { readLastFfi(code: false) }

private func lastFfiErrorCode() -> String { readLastFfi(code: true) }

private func ffiError(_ code: Int32, fallback: String) -> TendrilError {
  if code == TENDRIL_WOULD_BLOCK.rawValue {
    return .wouldBlock
  }
  if code == TENDRIL_EOF.rawValue {
    return .eof
  }
  // Both reads happen back to back on the failing thread; every other FFI call clears them.
  let msg = lastFfiError()
  let stableCode = lastFfiErrorCode()
  if let refusal = TendrilRefusal(code: stableCode) {
    return .refused(refusal)
  }
  return .ffi(code: code, message: msg.isEmpty ? fallback : msg)
}

private func takeOutCString(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
  guard let ptr else {
    return ""
  }
  defer { tendril_string_free(ptr) }
  return String(cString: ptr)
}

private func withValidatedCString<R>(
  _ value: String,
  name: String,
  _ body: (UnsafePointer<CChar>) throws -> R
) throws -> R {
  guard !value.utf8.contains(0) else {
    throw TendrilError.invalidArgument("\(name) contains interior NUL byte")
  }
  return try value.withCString(body)
}

private func withOptionalValidatedCString<R>(
  _ value: String?,
  name: String,
  _ body: (UnsafePointer<CChar>?) throws -> R
) throws -> R {
  guard let value else {
    return try body(nil)
  }
  return try withValidatedCString(value, name: name) { try body($0) }
}

#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security

internal final class SealedSwiftStateStore: @unchecked Sendable {
  private static let identityFile = "identity.sealed"
  private static let rosterFile = "roster.sealed"
  private static let bootstrapLockFile = ".identity.lock"
  private static let runtimeFiles = ["rt-roster.sealed", "rt-groups.sealed"]
  private static let identityAad = Data("tendril.identity.v1".utf8)
  private static let rosterAad = Data("tendril.roster.v1".utf8)

  private let lock = NSLock()
  private let dirUrl: URL
  internal let keychain: TendrilKeychainStore
  private let writeObserver: (@Sendable (String, Data) throws -> Void)?
  private let syncDirObserver: (@Sendable () throws -> Void)?
  private var pendingV2Commit = false

  init(
    dirPath: String,
    keychain: TendrilKeychainStore,
    writeObserver: (@Sendable (String, Data) throws -> Void)? = nil,
    syncDirObserver: (@Sendable () throws -> Void)? = nil
  ) throws {
    self.dirUrl = URL(fileURLWithPath: dirPath, isDirectory: true)
    self.keychain = keychain
    self.writeObserver = writeObserver
    self.syncDirObserver = syncDirObserver
    let fm = FileManager.default
    var isDir: ObjCBool = false
    if fm.fileExists(atPath: dirUrl.path, isDirectory: &isDir) {
      let attrs = try fm.attributesOfItem(atPath: dirUrl.path)
      if let fileType = attrs[.type] as? FileAttributeType, fileType == .typeSymbolicLink {
        throw TendrilError.invalidArgument("stateDir must not be a symlink")
      }
      guard isDir.boolValue else {
        throw TendrilError.invalidArgument("stateDir must be a directory")
      }
    } else {
      var createAttrs: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
      #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
      createAttrs[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
      #endif
      try fm.createDirectory(
        at: dirUrl,
        withIntermediateDirectories: true,
        attributes: createAttrs
      )
    }
    try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dirUrl.path)
    #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
    try Self.applyClassCProtection(toDirectory: dirUrl)
    #endif
    // Restoring an older runtime state file would roll back group membership and revocations,
    // so the directory never enters a backup.
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var url = dirUrl
    try url.setResourceValues(values)
  }

  #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
  internal static func applyClassCProtection(toDirectory dirUrl: URL) throws {
    let fm = FileManager.default
    try fm.setAttributes(
      [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
      ofItemAtPath: dirUrl.path
    )
    try applyClassCProtectionToExistingFiles(in: dirUrl)
  }

  internal static func applyClassCProtectionToExistingFiles(in dirUrl: URL) throws {
    let fm = FileManager.default
    let items = try fm.contentsOfDirectory(
      at: dirUrl,
      includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
      options: []
    )
    for item in items {
      let attrs = try fm.attributesOfItem(atPath: item.path)
      guard let fileType = attrs[.type] as? FileAttributeType, fileType == .typeRegular else {
        continue
      }
      try fm.setAttributes(
        [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
        ofItemAtPath: item.path
      )
    }
  }
  #endif

  private func readSealed(
    fileName: String,
    aad: Data,
    upgradeIfNeeded: Bool = false,
    deferCommit: Bool = false
  ) throws -> (json: String?, upgradedToV2: Bool) {
    let url = dirUrl.appendingPathComponent(fileName, isDirectory: false)
    let fm = FileManager.default
    guard fm.fileExists(atPath: url.path) else {
      return (nil, false)
    }
    let attrs = try fm.attributesOfItem(atPath: url.path)
    if let fileType = attrs[.type] as? FileAttributeType, fileType == .typeSymbolicLink {
      throw TendrilError.invalidArgument("\(fileName) must not be a symlink")
    }
    let sealed = try Data(contentsOf: url)
    var plain: Data
    let upgradedToV2: Bool
    if upgradeIfNeeded && sealed.first == TendrilKeychainStore.formatVersionV1 {
      let (maybeUpgraded, didUpgrade, decodedPlain) = try keychain.beginUpgradeV1ToV2(
        sealed,
        authenticating: aad
      )
      plain = decodedPlain
      do {
        if didUpgrade {
          try writeSealedBytes(fileName: fileName, sealed: maybeUpgraded)
          if deferCommit {
            pendingV2Commit = true
          } else {
            try keychain.commitV2Custody()
            pendingV2Commit = false
          }
        }
      } catch {
        if !plain.isEmpty {
          plain.resetBytes(in: 0..<plain.count)
        }
        throw error
      }
      upgradedToV2 = didUpgrade
    } else {
      let isV2 = (sealed.first == TendrilKeychainStore.formatVersionV2)
      plain = try keychain.openStateWithoutCommit(sealed, authenticating: aad)
      if isV2 {
        if deferCommit {
          pendingV2Commit = true
        } else {
          do {
            try syncDirectory()
            try keychain.commitV2Custody()
            pendingV2Commit = false
          } catch {
            if !plain.isEmpty {
              plain.resetBytes(in: 0..<plain.count)
            }
            throw error
          }
        }
      }
      upgradedToV2 = isV2
    }
    defer { plain.resetBytes(in: 0..<plain.count) }
    guard let s = String(data: plain, encoding: .utf8) else {
      throw TendrilKeychainError.invalidData
    }
    return (s, upgradedToV2)
  }

  private func writeSealed(
    fileName: String,
    json: String,
    aad: Data,
    deferCommit: Bool = false
  ) throws {
    var plain = Data(json.utf8)
    let sealed = try {
      defer { plain.resetBytes(in: 0..<plain.count) }
      return try keychain.sealStateWithoutCommit(plain, authenticating: aad)
    }()
    try writeSealedBytes(fileName: fileName, sealed: sealed)
    if sealed.first == TendrilKeychainStore.formatVersionV2 {
      if deferCommit {
        pendingV2Commit = true
      } else {
        try keychain.commitV2Custody()
        pendingV2Commit = false
      }
    }
  }

  private func syncDirectory() throws {
    try syncDirObserver?()
    #if canImport(Darwin)
    let fd = Darwin.open(dirUrl.path, O_RDONLY | O_CLOEXEC)
    guard fd >= 0 else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { _ = Darwin.close(fd) }
    if Darwin.fcntl(fd, F_FULLFSYNC) != 0 {
      let syncErr = errno
      if syncErr == ENOTSUP || syncErr == EINVAL || syncErr == ENOTTY {
        guard Darwin.fsync(fd) == 0 else {
          throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
      } else {
        throw POSIXError(POSIXErrorCode(rawValue: syncErr) ?? .EIO)
      }
    }
    #endif
  }

  private func writeSealedBytes(fileName: String, sealed: Data) throws {
    try writeObserver?(fileName, sealed)
    let target = dirUrl.appendingPathComponent(fileName, isDirectory: false)
    let tmp = dirUrl.appendingPathComponent(".\(fileName).\(UUID().uuidString).tmp")
    let fm = FileManager.default
    do {
      var attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o600]
      #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
      attrs[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
      #endif
      guard fm.createFile(atPath: tmp.path, contents: sealed, attributes: attrs) else {
        throw TendrilKeychainError.invalidData
      }
      let handle = try FileHandle(forWritingTo: tmp)
      defer { try? handle.close() }
      try handle.synchronize()
      if fm.fileExists(atPath: target.path) {
        _ = try fm.replaceItemAt(target, withItemAt: tmp)
      } else {
        try fm.moveItem(at: tmp, to: target)
      }
      #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
      try fm.setAttributes(
        [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
        ofItemAtPath: target.path
      )
      #endif
      try syncDirectory()
    } catch {
      try? fm.removeItem(at: tmp)
      throw error
    }
  }

  func loadIdentityJson(deferCommit: Bool = false) throws -> String? {
    lock.lock()
    defer { lock.unlock() }
    let shouldDefer = deferCommit || legacyRosterNeedsMigration()
    return try readSealed(
      fileName: Self.identityFile,
      aad: Self.identityAad,
      upgradeIfNeeded: true,
      deferCommit: shouldDefer
    ).json
  }

  func saveIdentityJson(_ json: String, deferCommit: Bool = false) throws {
    lock.lock()
    defer { lock.unlock() }
    let shouldDefer = deferCommit || legacyRosterNeedsMigration()
    try writeSealed(
      fileName: Self.identityFile,
      json: json,
      aad: Self.identityAad,
      deferCommit: shouldDefer
    )
  }

  /// Reads the pre-runtime binding roster, kept only to seed a directory once.
  func loadRosterJson(upgradeIfNeeded: Bool = false, deferCommit: Bool = false) throws -> String? {
    lock.lock()
    defer { lock.unlock() }
    return try readSealed(
      fileName: Self.rosterFile,
      aad: Self.rosterAad,
      upgradeIfNeeded: upgradeIfNeeded,
      deferCommit: deferCommit
    ).json
  }

  func commitV2CustodyIfNeeded() throws {
    lock.lock()
    defer { lock.unlock() }
    let identityUrl = dirUrl.appendingPathComponent(Self.identityFile, isDirectory: false)
    let identityExists = FileManager.default.fileExists(atPath: identityUrl.path)
    let identityIsV2: Bool
    if identityExists {
      let attrs = try FileManager.default.attributesOfItem(atPath: identityUrl.path)
      if let fileType = attrs[.type] as? FileAttributeType, fileType == .typeSymbolicLink {
        throw TendrilError.invalidArgument("\(Self.identityFile) must not be a symlink")
      }
      identityIsV2 = (try Data(contentsOf: identityUrl).first) == TendrilKeychainStore.formatVersionV2
    } else {
      identityIsV2 = false
    }
    if identityIsV2 || (pendingV2Commit && !identityExists) {
      try syncDirectory()
      try keychain.commitV2Custody()
      pendingV2Commit = false
    } else if identityExists && !identityIsV2 {
      pendingV2Commit = false
    }
  }

  func hasIdentityFile() -> Bool {
    FileManager.default.fileExists(
      atPath: dirUrl.appendingPathComponent(Self.identityFile, isDirectory: false).path
    )
  }

  /// Whether the legacy roster still needs migrating: it exists and the runtime has no state.
  func legacyRosterNeedsMigration() -> Bool {
    let fm = FileManager.default
    let path = { (name: String) in self.dirUrl.appendingPathComponent(name, isDirectory: false).path }
    return fm.fileExists(atPath: path(Self.rosterFile))
      && !Self.runtimeFiles.contains { fm.fileExists(atPath: path($0)) }
  }

  /// Deletes the pre-runtime binding roster, if any, without reading it. A concurrent delete is
  /// not an error.
  func deleteLegacyRoster() throws {
    lock.lock()
    defer { lock.unlock() }
    let path = dirUrl.appendingPathComponent(Self.rosterFile, isDirectory: false).path
    if Darwin.unlink(path) == 0 {
      try syncDirectory()
    } else if errno != ENOENT {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
  }

  /// Runs `body` holding an exclusive `flock` on `.identity.lock`, which serializes identity
  /// bootstrap across threads (each call opens its own descriptor) and processes.
  func withBootstrapLock<T>(_ body: () throws -> T) throws -> T {
    let path = dirUrl.appendingPathComponent(Self.bootstrapLockFile, isDirectory: false).path
    let fd = Darwin.open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard fd >= 0 else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { _ = Darwin.close(fd) }
    while flock(fd, LOCK_EX) != 0 {
      guard errno == EINTR else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
      }
    }
    do {
      let result = try body()
      #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
      try Self.applyClassCProtectionToExistingFiles(in: dirUrl)
      #endif
      return result
    } catch {
      #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
      try? Self.applyClassCProtectionToExistingFiles(in: dirUrl)
      #endif
      throw error
    }
  }
}
#endif

public enum TendrilCrypto {
  public static func deviceId(staticPub: Data) throws -> String {
    guard staticPub.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte staticPub")
    }
    var out: UnsafeMutablePointer<CChar>?
    let rc = staticPub.withUnsafeBytes { raw in
      tendril_device_id(raw.bindMemory(to: UInt8.self).baseAddress, &out)
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_device_id failed")
    }
    return takeOutCString(out)
  }

  public static func fingerprintHost(staticPub: Data) throws -> String {
    guard staticPub.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte staticPub")
    }
    var out: UnsafeMutablePointer<CChar>?
    let rc = staticPub.withUnsafeBytes { raw in
      tendril_fingerprint_host(raw.bindMemory(to: UInt8.self).baseAddress, &out)
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_fingerprint_host failed")
    }
    return takeOutCString(out)
  }

  public static func fingerprintDevice(staticPub: Data) throws -> String {
    guard staticPub.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte staticPub")
    }
    var out: UnsafeMutablePointer<CChar>?
    let rc = staticPub.withUnsafeBytes { raw in
      tendril_fingerprint_device(raw.bindMemory(to: UInt8.self).baseAddress, &out)
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_fingerprint_device failed")
    }
    return takeOutCString(out)
  }

  public static func pairingSas(handshakeHash: Data) throws -> String {
    guard handshakeHash.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte handshakeHash")
    }
    var out: UnsafeMutablePointer<CChar>?
    let rc = handshakeHash.withUnsafeBytes { raw in
      tendril_pairing_sas(raw.bindMemory(to: UInt8.self).baseAddress, &out)
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_pairing_sas failed")
    }
    return takeOutCString(out)
  }

  public static func computeCodeMac(code: String, handshakeHash: Data) throws -> Data {
    guard handshakeHash.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte handshakeHash")
    }
    var mac = Data(count: 32)
    let rc = try withValidatedCString(code, name: "code") { cCode in
      handshakeHash.withUnsafeBytes { hhRaw in
        mac.withUnsafeMutableBytes { macRaw in
          tendril_compute_code_mac(
            cCode,
            hhRaw.bindMemory(to: UInt8.self).baseAddress,
            macRaw.bindMemory(to: UInt8.self).baseAddress
          )
        }
      }
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_compute_code_mac failed")
    }
    return mac
  }

  public static func verifyRotationChainJson(
    pinnedSigningB64: String,
    pinnedStaticB64: String,
    pinnedSeq: UInt64,
    chainJson: String,
    curStaticB64: String,
    curSigningB64: String
  ) throws -> UInt64 {
    var finalSeq: UInt64 = 0
    let rc = try withValidatedCString(pinnedSigningB64, name: "pinnedSigningB64") { cPsig in
      try withValidatedCString(pinnedStaticB64, name: "pinnedStaticB64") { cPstat in
        try withValidatedCString(chainJson, name: "chainJson") { cChain in
          try withValidatedCString(curStaticB64, name: "curStaticB64") { cCstat in
            try withValidatedCString(curSigningB64, name: "curSigningB64") { cCsig in
              tendril_verify_rotation_chain_json(
                cPsig, cPstat, pinnedSeq, cChain, cCstat, cCsig, &finalSeq
              )
            }
          }
        }
      }
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_verify_rotation_chain_json failed")
    }
    return finalSeq
  }

  public static func verifyGrantJson(
    grantJson: String,
    issuerKeysJson: String,
    expectedSubject: String,
    expectedRootIssuer: String,
    requestedCap: String,
    nowUnix: UInt64,
    crlJson: String? = nil
  ) throws -> Bool {
    var allowed: UInt8 = 0
    let rc: Int32 = try withValidatedCString(grantJson, name: "grantJson") { cGrant in
      try withValidatedCString(issuerKeysJson, name: "issuerKeysJson") { cKeys in
        try withValidatedCString(expectedSubject, name: "expectedSubject") { cSubj in
          try withValidatedCString(expectedRootIssuer, name: "expectedRootIssuer") { cRoot in
            try withValidatedCString(requestedCap, name: "requestedCap") { cCap in
              try withOptionalValidatedCString(crlJson, name: "crlJson") { cCrl in
                tendril_verify_grant_json(
                  cGrant, cKeys, cSubj, cRoot, cCap, nowUnix, cCrl, &allowed
                )
              }
            }
          }
        }
      }
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_verify_grant_json failed")
    }
    return allowed == 1
  }

  public static func verifyWakeTag(
    secret: Data,
    tagB64: String,
    nowUnixSecs: UInt64 = UInt64(max(0, Int64(Date().timeIntervalSince1970)))
  ) throws -> Bool {
    guard secret.count == Int(TENDRIL_KEY_LEN) else {
      throw TendrilError.invalidArgument("expected \(TENDRIL_KEY_LEN)-byte wake secret")
    }
    var matched: UInt8 = 0
    let rc: Int32 = try withValidatedCString(tagB64, name: "tagB64") { cTag in
      secret.withUnsafeBytes { raw in
        tendril_verify_wake_tag(
          raw.bindMemory(to: UInt8.self).baseAddress,
          cTag,
          nowUnixSecs,
          &matched
        )
      }
    }
    guard rc == TENDRIL_OK.rawValue else {
      throw ffiError(rc, fallback: "tendril_verify_wake_tag failed")
    }
    return matched == 1
  }
}

/// A Tendril endpoint. With a `stateDir`, the identity is sealed by the Keychain in
/// `identity.sealed` and the runtime persists roster and group state itself in `rt-roster.sealed`
/// and `rt-groups.sealed`, sealed under a key derived from that identity.
public final class TendrilEndpoint: @unchecked Sendable {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false
  private let hasSealedStore: Bool
  private let isExtensionProfile: Bool
  /// Guards `pathMonitor`, `pathRefreshes` and `monitorClosed`. A monitor is swapped in or out
  /// with this lock held, and `start()` and `cancel()` run outside it. `close()` sets
  /// `monitorClosed` under it, so no monitor survives a close, and a monitor that was cancelled
  /// before it started refuses to start.
  private let monitorLock = NSLock()
  private var pathMonitor: TendrilPathMonitor?
  private var pathRefreshes = 0
  private var monitorClosed = false
  /// Last full transport configuration sent, as top-level JSON values. The C ABI replaces the
  /// whole configuration per call, so `configureRoutes` and `configureP2p` merge into this cache. Held across the
  /// FFI call to serialize configuration. The cache holds relay tickets and secrets, so
  /// `close()` clears it; Swift cannot zeroize the freed strings, so they linger until reused.
  private let configLock = NSLock()
  private var transportConfig: [String: Any] = [:]

  #if canImport(CryptoKit) && canImport(Security)
  public init(
    stateDir: String? = nil,
    hostId: String? = nil,
    keychainStore: TendrilKeychainStore? = nil,
    options: TendrilEndpointOptions = TendrilEndpointOptions()
  ) throws {
    self.isExtensionProfile = options.runtimeProfile == .extension
    if let stateDir, !stateDir.isEmpty {
      self.hasSealedStore = true
      let store = try SealedSwiftStateStore(
        dirPath: stateDir,
        keychain: keychainStore ?? TendrilKeychainStore()
      )
      self.handle = try withExpiringStateActivity {
        try store.withBootstrapLock {
          try Self.openSealed(store, stateDir: stateDir, hostId: hostId, options: options)
        }
      }
    } else {
      if options.runtimeProfile != .default || options.clientOnly || options.mldsaSigner != nil {
        throw TendrilError.invalidArgument("TendrilEndpointOptions require a non-empty stateDir")
      }
      self.hasSealedStore = false
      let raw = try withOptionalValidatedCString(hostId, name: "hostId") { cHost in
        tendril_endpoint_new_from_state(nil, nil, cHost)
      }
      guard let raw else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new_from_state failed")
      }
      self.handle = raw
      if let powerProfile = options.powerProfile {
        do {
          try configurePower(powerProfile: powerProfile)
        } catch {
          close()
          throw error
        }
      }
    }
  }
  #else
  public init(
    stateDir: String? = nil,
    hostId: String? = nil,
    options: TendrilEndpointOptions = TendrilEndpointOptions()
  ) throws {
    self.isExtensionProfile = options.runtimeProfile == .extension
    if options.runtimeProfile != .default || options.clientOnly || options.mldsaSigner != nil {
      guard let stateDir, !stateDir.isEmpty else {
        throw TendrilError.invalidArgument("TendrilEndpointOptions require a non-empty stateDir")
      }
      self.hasSealedStore = true
      let optionsJson = try encodeSealedEndpointOptionsJson(options)
      self.handle = try Self.newSealedWithOptions(
        stateDir, nil, nil, hostId, optionsJson, options.mldsaSigner
      )
    } else {
      self.hasSealedStore = (stateDir != nil && !stateDir!.isEmpty)
      let raw = try withOptionalValidatedCString(stateDir, name: "stateDir") { cd in
        try withOptionalValidatedCString(hostId, name: "hostId") { ch in
          tendril_endpoint_new(cd, ch)
        }
      }
      guard let raw else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new failed")
      }
      self.handle = raw
      if let powerProfile = options.powerProfile {
        do {
          try configurePower(powerProfile: powerProfile)
        } catch {
          close()
          throw error
        }
      }
    }
  }
  #endif

  private static func newSealedWithOptions(
    _ stateDir: String,
    _ identityJson: String?,
    _ rosterJson: String?,
    _ hostId: String?,
    _ optionsJson: String?,
    _ mldsaSigner: (any TendrilMlDsa65Provider)?
  ) throws -> OpaquePointer {
    let raw: OpaquePointer? = try withValidatedCString(stateDir, name: "stateDir") { cDir in
      try withOptionalValidatedCString(identityJson, name: "identityJson") { cId in
        try withOptionalValidatedCString(rosterJson, name: "rosterJson") { cRoster in
          try withOptionalValidatedCString(hostId, name: "hostId") { cHost in
            try withOptionalValidatedCString(optionsJson, name: "optionsJson") { cOpts in
              guard let mldsaSigner else {
                return tendril_endpoint_new_sealed_with_options(
                  cDir, cId, cRoster, cHost, cOpts, nil
                )
              }
              let bridge = CTendrilMlDsa65Bridge(provider: mldsaSigner)
              return try bridge.withCSigner { cSignerPtr, markTransferred -> OpaquePointer? in
                markTransferred()
                return tendril_endpoint_new_sealed_with_options(
                  cDir, cId, cRoster, cHost, cOpts, cSignerPtr
                )
              }
            }
          }
        }
      }
    }
    guard let raw else {
      throw ffiError(
        TENDRIL_ERR_INTERNAL.rawValue,
        fallback: "tendril_endpoint_new_sealed_with_options failed"
      )
    }
    return raw
  }

  #if canImport(CryptoKit) && canImport(Security)
  private static func resolveHardwareMlDsa65Signer(
    forExistingIdentity identity: String?,
    keychain: TendrilKeychainStore,
    options: TendrilEndpointOptions
  ) throws -> (any TendrilMlDsa65Provider)? {
    if let explicit = options.mldsaSigner {
      return explicit
    }
    if let identity {
      let parsed = try? JSONSerialization.jsonObject(with: Data(identity.utf8)) as? [String: Any]
      let version = (parsed?["version"] as? NSNumber)?.intValue
      guard version == 2 else {
        return nil
      }
      #if compiler(>=6.2)
      if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *),
        keychain.allowsHardwareMlDsaCustody
      {
        return try SecureEnclaveMlDsa65Provider.loadExisting(configuration: keychain.configuration)
      }
      #endif
      return nil
    }
    guard options.useHardwareMlDsaIfAvailable, keychain.allowsHardwareMlDsaCustody else {
      return nil
    }
    #if compiler(>=6.2)
    if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *),
      SecureEnclave.isAvailable
    {
      do {
        return try SecureEnclaveMlDsa65Provider(configuration: keychain.configuration)
      } catch {
        if keychain.configuration.custody == .secureEnclaveRequired
          || keychain.configuration.accessGroup != nil
          || !TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(error)
        {
          throw error
        }
        return nil
      }
    }
    #endif
    return nil
  }

  /// Saves a generated identity before any runtime state exists under it, then opens with it.
  /// The reopen syncs the directory, so `identity.sealed` is durable before the first runtime
  /// write, and seeds the runtime roster from a legacy `roster.sealed` only when needed.
  private static func openSealed(
    _ store: SealedSwiftStateStore,
    stateDir: String,
    hostId: String?,
    options: TendrilEndpointOptions
  ) throws -> OpaquePointer {
    let optionsJson = try encodeSealedEndpointOptionsJson(options)
    // Upgrade/read legacy roster.sealed and identity.sealed unconditionally with deferred v2
    // commitment so .sep-v2-committed persists only after writeSealedBytes directory sync,
    // runtime storage initialization, and legacy roster unlink+sync all succeed. If
    // identity.sealed is missing, an orphaned roster.sealed cannot belong to a freshly
    // generated identity and is discarded unread by deleteLegacyRoster() without seeding.
    let needsLegacyRoster = store.hasIdentityFile() && store.legacyRosterNeedsMigration()
    let seed: String? = needsLegacyRoster
      ? try store.loadRosterJson(upgradeIfNeeded: true, deferCommit: true)
      : nil
    var identity = try store.loadIdentityJson(deferCommit: true)
    let mldsaSigner = try resolveHardwareMlDsa65Signer(
      forExistingIdentity: identity,
      keychain: store.keychain,
      options: options
    )
    if identity == nil {
      let fresh = try newSealedWithOptions(
        stateDir, nil, nil, hostId, optionsJson, mldsaSigner
      )
      defer { tendril_endpoint_free(fresh) }
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_export_identity_json(fresh, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_export_identity_json failed")
      }
      let generated = takeOutCString(out)
      try store.saveIdentityJson(generated, deferCommit: true)
      identity = generated
    }
    let raw = try newSealedWithOptions(
      stateDir, identity, seed, hostId, optionsJson, mldsaSigner
    )
    do {
      try store.deleteLegacyRoster()
      try store.commitV2CustodyIfNeeded()
    } catch {
      tendril_endpoint_free(raw)
      throw error
    }
    return raw
  }
  #endif

  private func withExpiringStateActivityIfNeeded<T>(
    allowExpireClose: Bool = false,
    _ body: @escaping @Sendable () throws -> T
  ) throws -> T {
    try withExpiringActivityGuard(
      active: hasSealedStore && (!allowExpireClose || isExtensionProfile),
      allowExpireClose: allowExpireClose && isExtensionProfile,
      onAsyncClose: { [weak self] in self?.close() },
      body
    )
  }

  deinit {
    close()
  }

  public func close() {
    closePathMonitoring()
    configLock.lock()
    transportConfig = [:]
    configLock.unlock()
    cond.lock()
    guard let h = handle else {
      cond.unlock()
      return
    }
    let firstCloser = !closing
    closing = true
    if firstCloser {
      activeCalls += 1
    }
    cond.unlock()

    if firstCloser {
      _ = tendril_endpoint_close(h)
      cond.lock()
      activeCalls -= 1
      cond.broadcast()
    } else {
      cond.lock()
    }

    while activeCalls > 0 {
      cond.wait()
    }
    if let toFree = handle {
      handle = nil
      cond.unlock()
      tendril_endpoint_free(toFree)
    } else {
      cond.unlock()
    }
  }

  private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
    cond.lock()
    guard !closing, let h = handle else {
      cond.unlock()
      throw TendrilError.closed
    }
    activeCalls += 1
    cond.unlock()
    defer {
      cond.lock()
      activeCalls -= 1
      if activeCalls == 0 {
        cond.broadcast()
      }
      cond.unlock()
    }
    return try body(h)
  }

  public func infoJson() throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_info_json(h, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_info_json failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveDirect(listenAddr: String = "127.0.0.1:0") throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withValidatedCString(listenAddr, name: "listenAddr") { cAddr in
        tendril_endpoint_serve_direct(h, cAddr, &out)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_direct failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveRelay(relayUrl: String, expectedHost: String? = nil) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withValidatedCString(relayUrl, name: "relayUrl") { cUrl in
        try withOptionalValidatedCString(expectedHost, name: "expectedHost") { cHost in
          tendril_endpoint_serve_relay(h, cUrl, cHost, &out)
        }
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_relay failed")
      }
      return takeOutCString(out)
    }
  }

  /// Replaces the whole transport configuration. `configureRoutes` and `configureP2p` merge into
  /// the last one sent.
  public func configureTransportsJSON(_ transportConfigJson: String) throws {
    configLock.lock()
    defer { configLock.unlock() }
    try configureTransportsLocked(transportConfigJson)
  }

  /// Sends `transportConfigJson` and caches it on success. `configLock` must be held.
  private func configureTransportsLocked(_ transportConfigJson: String) throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(transportConfigJson, name: "transportConfigJson") { cCfg in
          tendril_endpoint_configure_transports_json(h, cCfg)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_configure_transports_json failed")
        }
      }
    }
    let parsed = try? JSONSerialization.jsonObject(with: Data(transportConfigJson.utf8))
    transportConfig = parsed as? [String: Any] ?? [:]
  }

  public func mintRelayTicket(
    relayHost: String,
    role: String? = nil,
    targetPubOrWildcard: String? = nil,
    ttlSecs: UInt64 = 300
  ) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withValidatedCString(relayHost, name: "relayHost") { cHost in
        try withOptionalValidatedCString(role, name: "role") { cRole in
          try withOptionalValidatedCString(targetPubOrWildcard, name: "targetPubOrWildcard") { cTarget in
            tendril_endpoint_mint_relay_ticket(h, cHost, cRole, cTarget, ttlSecs, &out)
          }
        }
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_mint_relay_ticket failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveRelayV2(
    relayUrl: String,
    expectedHost: String? = nil,
    peerIdOpt: String? = nil
  ) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withValidatedCString(relayUrl, name: "relayUrl") { cUrl in
        try withOptionalValidatedCString(expectedHost, name: "expectedHost") { cHost in
          try withOptionalValidatedCString(peerIdOpt, name: "peerIdOpt") { cPeer in
            tendril_endpoint_serve_relay_v2(h, cUrl, cHost, cPeer, &out)
          }
        }
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_relay_v2 failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveP2p(relayMode: String? = nil) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withOptionalValidatedCString(relayMode, name: "relayMode") { cMode in
        tendril_endpoint_serve_p2p(h, cMode, &out)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_p2p failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveP2pV2(relayMode: String? = nil, peerId: String? = nil) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withOptionalValidatedCString(relayMode, name: "relayMode") { cMode in
        try withOptionalValidatedCString(peerId, name: "peerId") { cPeer in
          tendril_endpoint_serve_p2p_v2(h, cMode, cPeer, &out)
        }
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_p2p_v2 failed")
      }
      return takeOutCString(out)
    }
  }

  public func issueCode(kind: String = "remote") throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(kind, name: "kind") { cKind in
          tendril_endpoint_issue_code(h, cKind, &out)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_issue_code failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func pairInitiate(
    endpoint: String,
    relayHost: String? = nil,
    code: String,
    deviceName: String,
    deviceKind: String = "ios"
  ) throws -> String {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(endpoint, name: "endpoint") { cEp in
          try withOptionalValidatedCString(relayHost, name: "relayHost") { cRh in
            try withValidatedCString(code, name: "code") { cCode in
              try withValidatedCString(deviceName, name: "deviceName") { cName in
                try withValidatedCString(deviceKind, name: "deviceKind") { cKind in
                  tendril_endpoint_pair_initiate(h, cEp, cRh, cCode, cName, cKind, &out)
                }
              }
            }
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_pair_initiate failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func pairAccept(timeoutMs: UInt64) throws -> String {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = tendril_endpoint_pair_accept(h, timeoutMs, &out)
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_pair_accept failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func pairV2Initiate(
    endpoint: String,
    relayHost: String? = nil,
    code: String,
    deviceName: String,
    deviceKind: String = "ios",
    pinnedHostJson: String? = nil
  ) throws -> String {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(endpoint, name: "endpoint") { cEp in
          try withOptionalValidatedCString(relayHost, name: "relayHost") { cRh in
            try withValidatedCString(code, name: "code") { cCode in
              try withValidatedCString(deviceName, name: "deviceName") { cName in
                try withValidatedCString(deviceKind, name: "deviceKind") { cKind in
                  try withOptionalValidatedCString(pinnedHostJson, name: "pinnedHostJson") { cPinned in
                    tendril_endpoint_pair_v2_initiate(h, cEp, cRh, cCode, cName, cKind, cPinned, &out)
                  }
                }
              }
            }
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_pair_v2_initiate failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func pairV2Accept(timeoutMs: UInt64) throws -> String {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = tendril_endpoint_pair_v2_accept(h, timeoutMs, &out)
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_pair_v2_accept failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func confirmPeer(peerId: String, sas: String? = nil) throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
          try withOptionalValidatedCString(sas, name: "sas") { cSas in
            tendril_endpoint_confirm_peer(h, cPeer, cSas)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_confirm_peer failed")
        }
      }
    }
  }

  public func mintGrant(peerId: String, capsJson: String, ttlSecs: UInt64 = 3600) throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
          try withValidatedCString(capsJson, name: "capsJson") { cCaps in
            tendril_endpoint_mint_grant(h, cPeer, cCaps, ttlSecs, &out)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_mint_grant failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Revokes `peerId` and clears its grants. A `nil` `notify` follows the endpoint refusal
  /// policy, which records a refusal notice, so the peer gets an authenticated refusal on its
  /// next session attempt. `notify: false` revokes silently and `true` records a notice when the policy TTL allows.
  public func revokePeer(peerId: String, notify: Bool? = nil) throws {
    let options = notify.map { "{\"notify\":\($0)}" }
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
          try withOptionalValidatedCString(options, name: "options") { cOptions in
            tendril_endpoint_revoke_peer_with_options(h, cPeer, cOptions)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_revoke_peer_with_options failed")
        }
      }
    }
  }

  /// Sets and persists the host refusal policy. `pending` refuses unconfirmed peers with close
  /// code 4004. `revokedNoticeTtlSecs` is the lifetime of a notice recorded at revocation, and 0
  /// records none.
  public func setRefusalPolicy(pending: Bool, revokedNoticeTtlSecs: UInt64) throws {
    let policy = "{\"pending\":\(pending),\"revoked_notice_ttl_secs\":\(revokedNoticeTtlSecs)}"
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(policy, name: "policy") { cPolicy in
          tendril_endpoint_set_refusal_policy_json(h, cPolicy)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_set_refusal_policy_json failed")
        }
      }
    }
  }

  /// Drops the refusal notice of `peerId`, which stays revoked. Throws for an unknown peer.
  public func clearRefusalNotice(_ peerId: String) throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
          tendril_endpoint_clear_refusal_notice(h, cPeer)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_clear_refusal_notice failed")
        }
      }
    }
  }

  public func addTrustAnchor(anchorId: String, signingPub: Data) throws {
    guard signingPub.count == Int(TENDRIL_SIGNING_PUB_LEN) else {
      throw TendrilError.invalidArgument(
        "signingPub must be \(TENDRIL_SIGNING_PUB_LEN) bytes"
      )
    }
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(anchorId, name: "anchorId") { cAnchor in
          signingPub.withUnsafeBytes { keyRaw in
            tendril_endpoint_add_trust_anchor(
              h, cAnchor, keyRaw.bindMemory(to: UInt8.self).baseAddress, signingPub.count
            )
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_add_trust_anchor failed")
        }
      }
    }
  }

  public func revokeTrustAnchor(anchorId: String) throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(anchorId, name: "anchorId") { cAnchor in
          tendril_endpoint_revoke_trust_anchor(h, cAnchor)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_revoke_trust_anchor failed")
        }
      }
    }
  }

  public func mintEnrollmentToken(
    targetHostId: String,
    subject: String? = nil,
    ttlSecs: UInt64 = 900
  ) throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(targetHostId, name: "targetHostId") { cTarget in
          try withOptionalValidatedCString(subject, name: "subject") { cSubj in
            tendril_endpoint_mint_enrollment_token(h, cTarget, cSubj, ttlSecs, &out)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_mint_enrollment_token failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func enrollInitiate(
    endpoint: String,
    relayHost: String? = nil,
    hostId: String,
    hostStaticPub: Data,
    hostSigningPub: Data,
    hostRotationSeq: UInt64 = 0,
    tokenJson: String,
    name: String = "ios-machine",
    kind: String = "machine"
  ) throws -> String {
    guard hostStaticPub.count == Int(TENDRIL_KEY_LEN) else {
      throw TendrilError.invalidArgument("hostStaticPub must be \(TENDRIL_KEY_LEN) bytes")
    }
    guard hostSigningPub.count == Int(TENDRIL_SIGNING_PUB_LEN)
      || hostSigningPub.count == Int(TENDRIL_SIGNING_HASH_LEN)
    else {
      throw TendrilError.invalidArgument(
        "hostSigningPub must be \(TENDRIL_SIGNING_PUB_LEN) or \(TENDRIL_SIGNING_HASH_LEN) bytes"
      )
    }
    return try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(endpoint, name: "endpoint") { cEp in
          try withOptionalValidatedCString(relayHost, name: "relayHost") { cRh in
            try withValidatedCString(hostId, name: "hostId") { cHost in
              try withValidatedCString(tokenJson, name: "tokenJson") { cToken in
                try withValidatedCString(name, name: "name") { cName in
                  try withValidatedCString(kind, name: "kind") { cKind in
                    hostStaticPub.withUnsafeBytes { stRaw in
                      hostSigningPub.withUnsafeBytes { sgRaw in
                        tendril_endpoint_enroll_initiate(
                          h,
                          cEp,
                          cRh,
                          cHost,
                          stRaw.bindMemory(to: UInt8.self).baseAddress,
                          sgRaw.bindMemory(to: UInt8.self).baseAddress,
                          hostSigningPub.count,
                          hostRotationSeq,
                          cToken,
                          cName,
                          cKind,
                          &out
                        )
                      }
                    }
                  }
                }
              }
            }
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_enroll_initiate failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Opens a Wire v1 session. A `nil` or empty `endpoint` dials the peer's stored routes; a
  /// non-empty one is an explicit operator endpoint, dialed alone.
  public func connect(
    endpoint: String? = nil,
    relayHost: String? = nil,
    targetHostId: String,
    grantJson: String? = nil
  ) throws -> TendrilSession {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        let raw = try withOptionalValidatedCString(endpoint, name: "endpoint") { cEp in
          try withOptionalValidatedCString(relayHost, name: "relayHost") { cRh in
            try withValidatedCString(targetHostId, name: "targetHostId") { cTarget in
              try withOptionalValidatedCString(grantJson, name: "grantJson") { cGrant in
                tendril_session_connect(h, cEp, cRh, cTarget, cGrant)
              }
            }
          }
        }
        guard let raw else {
          throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_connect failed")
        }
        return TendrilSession(
          handle: raw,
          hasSealedStore: self.hasSealedStore,
          isExtensionProfile: self.isExtensionProfile
        )
      }
    }
  }

  // MARK: Pairing URIs and routes

  /// Issues a single-use pairing URI built from the announced route set. Hints come only from
  /// the announced set (served listeners, `advertisedEndpoints` and, with `advertise: auto`,
  /// enumerated addresses). Returns `{"uri", "code_kind", "dropped", "uri_len", "qr_version_m",
  /// "route_seq"}` as JSON.
  public func issuePairingUri(
    kind: String? = nil,
    hostName: String? = nil,
    signRoutes: Bool? = nil
  ) throws -> String {
    let options = try transportOptionsJSON([
      "kind": kind, "host_name": hostName, "sign_routes": signRoutes,
    ])
    return try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withOptionalValidatedCString(options, name: "options") { cOpts in
          tendril_endpoint_issue_pairing_uri(h, cOpts, &out)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_issue_pairing_uri failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Pairs from a scanned Wire v1 pairing URI by racing its hints. `routePolicy` is
  /// `"all_signed"` (default), `"committed_only"` or `"none"`; `saveRoute` stores the committed
  /// route of an unsigned URI; `endpoint` is dialed alone and stored as an operator route.
  public func pairUri(
    _ pairingUri: String,
    name: String? = nil,
    deviceKind: String? = "ios",
    routePolicy: String? = nil,
    saveRoute: Bool? = nil,
    endpoint: String? = nil,
    code: String? = nil
  ) throws -> String {
    try pairUriCall(
      "tendril_endpoint_pair_uri", .v1, pairingUri, name, deviceKind,
      routePolicy, saveRoute, endpoint, code)
  }

  /// Pairs from a scanned pairing URI over Wire v2, one rung at a time. Options as `pairUri`.
  public func pairV2Uri(
    _ pairingUri: String,
    name: String? = nil,
    deviceKind: String? = "ios",
    routePolicy: String? = nil,
    saveRoute: Bool? = nil,
    endpoint: String? = nil,
    code: String? = nil
  ) throws -> String {
    try pairUriCall(
      "tendril_endpoint_pair_v2_uri", .v2, pairingUri, name, deviceKind,
      routePolicy, saveRoute, endpoint, code)
  }

  private enum PairUriWire: Sendable {
    case v1
    case v2
  }

  private func pairUriCall(
    _ fnName: String,
    _ wire: PairUriWire,
    _ pairingUri: String,
    _ name: String?,
    _ deviceKind: String?,
    _ routePolicy: String?,
    _ saveRoute: Bool?,
    _ endpoint: String?,
    _ code: String?
  ) throws -> String {
    let options = try transportOptionsJSON([
      "route_policy": routePolicy, "save_route": saveRoute, "endpoint": endpoint, "code": code,
    ])
    return try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(pairingUri, name: "pairingUri") { cUri in
          try withOptionalValidatedCString(name, name: "name") { cName in
            try withOptionalValidatedCString(deviceKind, name: "deviceKind") { cKind in
              try withOptionalValidatedCString(options, name: "options") { cOpts in
                switch wire {
                case .v1:
                  return tendril_endpoint_pair_uri(h, cUri, cName, cKind, cOpts, &out)
                case .v2:
                  return tendril_endpoint_pair_v2_uri(h, cUri, cName, cKind, cOpts, &out)
                }
              }
            }
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "\(fnName) failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Opens a session with options. `wire` is 1 or 2; a `nil` `endpoint` dials the stored routes;
  /// a `recoveryUri` (fresh pairing URI of the peer) has its keys checked before `msg3`, and a
  /// signed one replaces the signed routes when newer or with `replaceRoutes`. `relayHost` is the
  /// expected relay host of an explicit `endpoint` (the Iroh relay mode for `iroh://`).
  public func connectWithOptions(
    targetHostId: String,
    wire: Int = 1,
    grantJson: String? = nil,
    endpoint: String? = nil,
    recoveryUri: String? = nil,
    replaceRoutes: Bool? = nil,
    routePolicy: String? = nil,
    relayHost: String? = nil,
    idleTimeoutMs: UInt64? = nil
  ) throws -> TendrilSession {
    var fields: [String: Any?] = [
      "wire": wire, "endpoint": endpoint, "recovery_uri": recoveryUri,
      "replace_routes": replaceRoutes, "route_policy": routePolicy, "relay_host": relayHost,
      "idle_timeout_ms": idleTimeoutMs,
    ]
    if let grantJson {
      guard let obj = try? JSONSerialization.jsonObject(with: Data(grantJson.utf8)) else {
        throw TendrilError.invalidArgument("grantJson is not valid JSON")
      }
      fields["grant"] = obj
    }
    let options = try transportOptionsJSON(fields)
    return try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        let raw = try withValidatedCString(targetHostId, name: "targetHostId") { cTarget in
          try withOptionalValidatedCString(options, name: "options") { cOpts in
            tendril_session_connect_with_options(h, cTarget, cOpts)
          }
        }
        guard let raw else {
          throw ffiError(
            TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_connect_with_options failed")
        }
        return TendrilSession(
          handle: raw,
          hasSealedStore: self.hasSealedStore,
          isExtensionProfile: self.isExtensionProfile
        )
      }
    }
  }

  /// Replaces the operator routes of `peerId` with `routes` (at most six endpoint strings). One
  /// bad entry rejects the list and nothing is written.
  public func setPeerRoutes(peerId: String, routes: [String]) throws {
    for route in routes where route.utf8.contains(0) {
      throw TendrilError.invalidArgument("routes contains interior NUL byte")
    }
    let data = try JSONSerialization.data(withJSONObject: routes)
    let json = String(decoding: data, as: UTF8.self)
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
          try withValidatedCString(json, name: "routes") { cRoutes in
            tendril_endpoint_set_peer_routes(h, cPeer, cRoutes)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_set_peer_routes failed")
        }
      }
    }
  }

  /// Stored routes of `peerId` as JSON: `{"routes": [{"hint", "source"}], "route_meta":
  /// {"seq", "issued_at", "origin"} | null, "last_route_set": {"outcome", "seq"} | null}`.
  public func peerRoutes(peerId: String) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
        tendril_endpoint_peer_routes(h, cPeer, &out)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_peer_routes failed")
      }
      return takeOutCString(out)
    }
  }

  /// Clears stored routes of `peerId`. `source` is `nil` or `"operator"` (operator routes),
  /// `"signed"`, `"committed"` or `"all"`. The route metadata is kept.
  public func clearPeerRoutes(peerId: String, source: String? = nil) throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
          try withOptionalValidatedCString(source, name: "source") { cSource in
            tendril_endpoint_clear_peer_routes(h, cPeer, cSource)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_clear_peer_routes failed")
        }
      }
    }
  }

  /// Applies a fresh signed pairing URI to the paired host whose keys it carries, offline.
  /// Returns `{"peer_id", "applied", "reason", "route_seq"}` as JSON.
  public func applyRouteUri(
    _ pairingUri: String,
    replaceRoutes: Bool? = nil,
    routePolicy: String? = nil
  ) throws -> String {
    let options = try transportOptionsJSON(["replace_routes": replaceRoutes, "route_policy": routePolicy])
    return try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withValidatedCString(pairingUri, name: "pairingUri") { cUri in
          try withOptionalValidatedCString(options, name: "options") { cOpts in
            tendril_endpoint_apply_route_uri(h, cUri, cOpts, &out)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_apply_route_uri failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Re-scans the host's addresses and republishes the announced route set. `nil` enumerates
  /// the interfaces natively; a snapshot is the complete network list
  /// `{"networks": [{"id", "iface", "if_index", "transports", "addrs"}]}`. Returns
  /// `{"route_seq", "changed"}` as JSON.
  @discardableResult
  public func refreshRoutes(snapshotJson: String? = nil) throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withOptionalValidatedCString(snapshotJson, name: "snapshotJson") { cSnap in
          tendril_endpoint_refresh_routes(h, cSnap, &out)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_endpoint_refresh_routes failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Sets the route keys of the transport configuration. `advertise` is `"auto"` or
  /// `"explicit"`, `routePolicy` is `"all_signed"`, `"committed_only"` or `"none"`, and
  /// `relayAuthOrigins` are `scheme://host[:port]` origins that may receive relay admission
  /// material. Only the arguments passed change; every other key of the last transport
  /// configuration sent (relay credentials, P2P, wake) is kept.
  public func configureRoutes(
    advertisedEndpoints: [String]? = nil,
    relayAuthOrigins: [String]? = nil,
    advertise: String? = nil,
    routePolicy: String? = nil,
    signRoutes: Bool? = nil
  ) throws {
    try mergeTransportConfig([
      "advertised_endpoints": advertisedEndpoints, "relay_auth_origins": relayAuthOrigins,
      "advertise": advertise, "route_policy": routePolicy, "sign_routes": signRoutes,
    ])
  }

  /// Sets the network keys of the P2P transport configuration. `portMapping` (`p2p_port_mapping`,
  /// defaulting to `true` on macOS listeners and `false` on iOS listeners and all dialers) set
  /// to `false` stops a P2P endpoint from probing the router for a UPnP, NAT-PMP or PCP mapping.
  /// `bindAddrs` (`p2p_bind_addrs`) holds at most one IPv4 and one IPv6 socket address such as
  /// `"0.0.0.0:0"` and `"[::]:0"`; an empty list means every interface. `ephemeral`
  /// (`p2p_ephemeral`) uses an ephemeral node key and disables `Pkarr` publishing on Day-1
  /// `serveP2p` unless `p2p_pkarr` is also enabled. An invalid entry throws an error naming
  /// `p2p_bind_addrs`. Only the arguments passed change; every other key of the last transport
  /// configuration sent is kept.
  public func configureP2p(
    portMapping: Bool? = nil,
    bindAddrs: [String]? = nil,
    ephemeral: Bool? = nil
  ) throws {
    try mergeTransportConfig([
      "p2p_port_mapping": portMapping,
      "p2p_bind_addrs": bindAddrs,
      "p2p_ephemeral": ephemeral,
    ])
  }

  /// Sets `power_profile` and `wake_retry_max_delay_ms`, keeping every other key of the last full
  /// transport configuration sent.
  public func configurePower(
    powerProfile: TendrilPowerProfile? = nil,
    wakeRetryMaxDelayMs: UInt64? = nil
  ) throws {
    try mergeTransportConfig([
      "power_profile": powerProfile?.rawValue,
      "wake_retry_max_delay_ms": wakeRetryMaxDelayMs,
    ])
  }

  /// Merges `fields` into the last full transport configuration and sends the result.
  private func mergeTransportConfig(_ fields: [String: Any?]) throws {
    let changes = try transportOptions(fields)
    configLock.lock()
    defer { configLock.unlock() }
    let merged = transportConfig.merging(changes) { _, new in new }
    let data = try JSONSerialization.data(withJSONObject: merged, options: [.sortedKeys])
    try configureTransportsLocked(String(decoding: data, as: UTF8.self))
  }

  private func transportOptions(_ fields: [String: Any?]) throws -> [String: Any] {
    var obj: [String: Any] = [:]
    for (key, value) in fields {
      guard let value else { continue }
      if let s = value as? String, s.utf8.contains(0) {
        throw TendrilError.invalidArgument("\(key) contains interior NUL byte")
      }
      if let list = value as? [String], list.contains(where: { $0.utf8.contains(0) }) {
        throw TendrilError.invalidArgument("\(key) contains interior NUL byte")
      }
      obj[key] = value
    }
    return obj
  }

  private func transportOptionsJSON(_ fields: [String: Any?]) throws -> String? {
    let obj = try transportOptions(fields)
    if obj.isEmpty {
      return nil
    }
    let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
    return String(decoding: data, as: UTF8.self)
  }

  // MARK: Path monitoring

  /// Starts an `NWPathMonitor` that calls `refreshRoutes()` on every path update, so the
  /// announced route set follows the host's network changes. Calling it again replaces the
  /// monitor. `close()` stops it. The first update marks the endpoint as a route host.
  /// Throws `TendrilError.closed` on a closed endpoint. On platforms without `Network` this is a
  /// documented no-op, and `isPathMonitoring` stays false.
  public func startPathMonitoring(queue: DispatchQueue = DispatchQueue(label: "dev.tendril.path")) throws {
    #if canImport(Network)
    let monitor = TendrilPathMonitor(queue: queue) { [weak self] in
      guard let self, (try? self.refreshRoutes()) != nil else { return }
      self.monitorLock.lock()
      self.pathRefreshes += 1
      self.monitorLock.unlock()
    }
    monitorLock.lock()
    guard !monitorClosed else {
      monitorLock.unlock()
      throw TendrilError.closed
    }
    let previous = pathMonitor
    pathMonitor = monitor
    monitorLock.unlock()
    // Started and cancelled outside the lock; a monitor cancelled meanwhile refuses to start.
    if monitor.start() {
      try? setExternalPathMonitor(true)
    }
    previous?.cancel()
    #endif
  }

  public func stopPathMonitoring() {
    monitorLock.lock()
    let monitor = pathMonitor
    pathMonitor = nil
    monitorLock.unlock()
    monitor?.cancel()
    if monitor != nil {
      try? setExternalPathMonitor(false)
    }
  }

  /// Notifies the runtime announcer whether an external OS path monitor owns interface changes,
  /// suppressing periodic background route polling while active.
  public func setExternalPathMonitor(_ active: Bool) throws {
    try withHandle { h in
      let rc = tendril_endpoint_set_external_path_monitor(h, active ? 1 : 0)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_set_external_path_monitor failed")
      }
    }
  }

  /// Marks the monitor lifecycle closed and cancels the running monitor.
  private func closePathMonitoring() {
    monitorLock.lock()
    monitorClosed = true
    let monitor = pathMonitor
    pathMonitor = nil
    monitorLock.unlock()
    monitor?.cancel()
  }

  /// Runs the monitor's path-update handler once, as an `NWPathMonitor` update would.
  internal func firePathUpdate() {
    monitorLock.lock()
    let monitor = pathMonitor
    monitorLock.unlock()
    monitor?.fire()
  }

  /// Path updates that refreshed the routes so far.
  internal var pathRefreshCount: Int {
    monitorLock.lock()
    defer { monitorLock.unlock() }
    return pathRefreshes
  }

  /// True when the installed monitor, if any, has been cancelled.
  internal var pathMonitorIsCancelled: Bool {
    monitorLock.lock()
    defer { monitorLock.unlock() }
    return pathMonitor?.isCancelled ?? false
  }

  /// Number of cached transport configuration keys; zero after `close()`.
  internal var cachedTransportKeyCount: Int {
    configLock.lock()
    defer { configLock.unlock() }
    return transportConfig.count
  }

  /// Cached value of one transport configuration key, if set.
  internal func cachedTransportValue(_ key: String) -> Any? {
    configLock.lock()
    defer { configLock.unlock() }
    return transportConfig[key]
  }

  /// True while a path monitor is running.
  public var isPathMonitoring: Bool {
    monitorLock.lock()
    defer { monitorLock.unlock() }
    return pathMonitor != nil
  }

  public func acceptSession(timeoutMs: UInt64) throws -> TendrilSession {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        guard let raw = tendril_session_accept(h, timeoutMs) else {
          throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_accept failed")
        }
        return TendrilSession(
          handle: raw,
          hasSealedStore: self.hasSealedStore,
          isExtensionProfile: self.isExtensionProfile
        )
      }
    }
  }

  /// Opens a Wire v2 session. A `nil` or empty `endpoint` dials the peer's stored routes.
  public func connectV2(
    endpoint: String? = nil,
    relayHost: String? = nil,
    targetHostId: String,
    grantJson: String? = nil
  ) throws -> TendrilSession {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        let raw = try withOptionalValidatedCString(endpoint, name: "endpoint") { cEp in
          try withOptionalValidatedCString(relayHost, name: "relayHost") { cRh in
            try withValidatedCString(targetHostId, name: "targetHostId") { cTarget in
              try withOptionalValidatedCString(grantJson, name: "grantJson") { cGrant in
                tendril_session_connect_v2(h, cEp, cRh, cTarget, cGrant)
              }
            }
          }
        }
        guard let raw else {
          throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_connect_v2 failed")
        }
        return TendrilSession(
          handle: raw,
          hasSealedStore: self.hasSealedStore,
          isExtensionProfile: self.isExtensionProfile
        )
      }
    }
  }

  public func acceptV2(timeoutMs: UInt64) throws -> TendrilSession {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        guard let raw = tendril_session_accept_v2(h, timeoutMs) else {
          throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_accept_v2 failed")
        }
        return TendrilSession(
          handle: raw,
          hasSealedStore: self.hasSealedStore,
          isExtensionProfile: self.isExtensionProfile
        )
      }
    }
  }
}

/// Calls `onChange` for every `NWPathMonitor` path update, on `queue`.
internal final class TendrilPathMonitor: @unchecked Sendable {
  #if canImport(Network)
  private let monitor = NWPathMonitor()
  #endif
  private let queue: DispatchQueue
  private let onChange: @Sendable () -> Void
  private let lock = NSLock()
  private var cancelled = false

  init(queue: DispatchQueue, onChange: @escaping @Sendable () -> Void) {
    self.queue = queue
    self.onChange = onChange
  }

  /// Starts the monitor unless it was cancelled first. Returns whether it started.
  @discardableResult
  func start() -> Bool {
    #if canImport(Network)
    if isCancelled {
      return false
    }
    monitor.pathUpdateHandler = { [weak self] _ in
      self?.fire()
    }
    monitor.start(queue: queue)
    return true
    #else
    return false
    #endif
  }

  var isCancelled: Bool {
    lock.lock()
    defer { lock.unlock() }
    return cancelled
  }

  func fire() {
    lock.lock()
    let live = !cancelled
    lock.unlock()
    if live {
      onChange()
    }
  }

  func cancel() {
    lock.lock()
    cancelled = true
    lock.unlock()
    #if canImport(Network)
    monitor.cancel()
    #endif
  }
}

public final class TendrilSession: @unchecked Sendable {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false
  private let hasSealedStore: Bool
  private let isExtensionProfile: Bool

  internal init(
    handle: OpaquePointer,
    hasSealedStore: Bool = false,
    isExtensionProfile: Bool = false
  ) {
    self.handle = handle
    self.hasSealedStore = hasSealedStore
    self.isExtensionProfile = isExtensionProfile
  }

  private func withExpiringStateActivityIfNeeded<T>(
    allowExpireClose: Bool = false,
    _ body: @escaping @Sendable () throws -> T
  ) throws -> T {
    try withExpiringActivityGuard(
      active: hasSealedStore && (!allowExpireClose || isExtensionProfile),
      allowExpireClose: allowExpireClose && isExtensionProfile,
      onAsyncClose: { [weak self] in self?.free() },
      body
    )
  }

  deinit {
    free()
  }

  public func free() {
    cond.lock()
    guard let h = handle else {
      cond.unlock()
      return
    }
    let firstCloser = !closing
    closing = true
    if firstCloser {
      activeCalls += 1
    }
    cond.unlock()

    if firstCloser {
      _ = tendril_session_shutdown(h)
      cond.lock()
      activeCalls -= 1
      cond.broadcast()
    } else {
      cond.lock()
    }

    while activeCalls > 0 {
      cond.wait()
    }
    if let toFree = handle {
      handle = nil
      cond.unlock()
      tendril_session_free(toFree)
    } else {
      cond.unlock()
    }
  }

  private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
    cond.lock()
    guard !closing, let h = handle else {
      cond.unlock()
      throw TendrilError.closed
    }
    activeCalls += 1
    cond.unlock()
    defer {
      cond.lock()
      activeCalls -= 1
      if activeCalls == 0 {
        cond.broadcast()
      }
      cond.unlock()
    }
    return try body(h)
  }

  /// Authenticated roster peer identifier of this session. Evaluate capabilities separately via `authorize(_:)`.
  public func peerId() throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_session_peer_id(h, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_peer_id failed")
      }
      return takeOutCString(out)
    }
  }

  public func sendData(_ data: Data) throws {
    try withHandle { h in
      let rc = data.withUnsafeBytes { raw in
        tendril_session_send_data(h, raw.bindMemory(to: UInt8.self).baseAddress, data.count)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_send_data failed")
      }
    }
  }

  public func pollEvent(timeoutMs: UInt64) throws -> String {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = tendril_session_poll_event(h, timeoutMs, &out)
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_session_poll_event failed")
        }
        return takeOutCString(out)
      }
    }
  }

  public func authorize(_ requestedCap: String) throws -> Bool {
    try withHandle { h in
      var allowed: UInt8 = 0
      let rc = try withValidatedCString(requestedCap, name: "requestedCap") { cCap in
        tendril_session_authorize(h, cCap, &allowed)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_authorize failed")
      }
      return allowed == 1
    }
  }

  public func rekey() throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = tendril_session_rekey(h)
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_session_rekey failed")
        }
      }
    }
  }

  public func close(code: UInt16 = 1000, reason: String = "") throws {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        let rc = try withValidatedCString(reason, name: "reason") { cReason in
          tendril_session_close(h, code, cReason)
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_session_close failed")
        }
      }
    }
  }
}

extension TendrilEndpoint {
  private func manifestCall(
    _ name: String,
    _ call: @escaping @Sendable (OpaquePointer, inout UnsafeMutablePointer<CChar>?) throws -> Int32
  ) throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try call(h, &out)
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "\(name) failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Creates a group rooted at this endpoint and returns the signed manifest JSON. Group APIs need a
  /// `stateDir`; an endpoint without one throws an invalid-argument error. `endpointsJson` is nil or
  /// a JSON array of strings.
  public func groupCreate(name: String, minWireVersion: UInt8 = 1, endpointsJson: String? = nil) throws -> String {
    try manifestCall("tendril_group_create") { h, out in
      try withValidatedCString(name, name: "name") { cName in
        try withOptionalValidatedCString(endpointsJson, name: "endpointsJson") { cEndpoints in
          tendril_group_create(h, cName, minWireVersion, cEndpoints, &out)
        }
      }
    }
  }

  public func groupAddMember(
    groupId: String,
    peerId: String,
    capsJson: String? = nil,
    endpointsJson: String? = nil
  ) throws -> String {
    try manifestCall("tendril_group_add_member") { h, out in
      try withValidatedCString(groupId, name: "groupId") { cGroup in
        try withValidatedCString(peerId, name: "peerId") { cPeer in
          try withOptionalValidatedCString(capsJson, name: "capsJson") { cCaps in
            try withOptionalValidatedCString(endpointsJson, name: "endpointsJson") { cEndpoints in
              tendril_group_add_member(h, cGroup, cPeer, cCaps, cEndpoints, &out)
            }
          }
        }
      }
    }
  }

  public func groupRemoveMember(groupId: String, peerId: String) throws -> String {
    try manifestCall("tendril_group_remove_member") { h, out in
      try withValidatedCString(groupId, name: "groupId") { cGroup in
        try withValidatedCString(peerId, name: "peerId") { cPeer in
          tendril_group_remove_member(h, cGroup, cPeer, &out)
        }
      }
    }
  }

  /// Ingests a manifest received from the authenticated peer `senderPeerId`; returns its group id.
  public func groupIngestManifest(manifestJson: String, senderPeerId: String) throws -> String {
    try manifestCall("tendril_group_ingest_manifest") { h, out in
      try withValidatedCString(manifestJson, name: "manifestJson") { cManifest in
        try withValidatedCString(senderPeerId, name: "senderPeerId") { cSender in
          tendril_group_ingest_manifest(h, cManifest, cSender, &out)
        }
      }
    }
  }

  /// Opens the group pool. A non-nil `listenAddr` also binds a direct listener the group serves (see
  /// `TendrilGroup.localEndpoint()`). Configure transports before the first call. Call `serveRelay`
  /// before the first call too: the hub leaves the relay hosts served that way to the endpoint only
  /// for calls that returned before it, and a later `serveRelay` on a relay host in the member's own
  /// entry competes with the group.
  public func openGroup(groupId: String, listenAddr: String? = nil) throws -> TendrilGroup {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var raw: OpaquePointer?
        let rc = try withValidatedCString(groupId, name: "groupId") { cGroup in
          try withOptionalValidatedCString(listenAddr, name: "listenAddr") { cListen in
            tendril_group_open(h, cGroup, cListen, &raw)
          }
        }
        guard rc == TENDRIL_OK.rawValue, let raw else {
          throw ffiError(rc, fallback: "tendril_group_open failed")
        }
        return TendrilGroup(
          handle: raw,
          hasSealedStore: self.hasSealedStore,
          isExtensionProfile: self.isExtensionProfile
        )
      }
    }
  }
}

public final class TendrilGroup: @unchecked Sendable {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false
  private let hasSealedStore: Bool
  private let isExtensionProfile: Bool

  internal init(
    handle: OpaquePointer,
    hasSealedStore: Bool = false,
    isExtensionProfile: Bool = false
  ) {
    self.handle = handle
    self.hasSealedStore = hasSealedStore
    self.isExtensionProfile = isExtensionProfile
  }

  private func withExpiringStateActivityIfNeeded<T>(
    allowExpireClose: Bool = false,
    _ body: @escaping @Sendable () throws -> T
  ) throws -> T {
    try withExpiringActivityGuard(
      active: hasSealedStore && (!allowExpireClose || isExtensionProfile),
      allowExpireClose: allowExpireClose && isExtensionProfile,
      onAsyncClose: { [weak self] in self?.close() },
      body
    )
  }

  deinit {
    close()
  }

  /// Closes the group handle and frees it. Idempotent; a `pollEvent` already waiting returns promptly
  /// and throws `.eof`.
  public func close() {
    cond.lock()
    guard let h = handle else {
      cond.unlock()
      return
    }
    let firstCloser = !closing
    closing = true
    if firstCloser {
      activeCalls += 1
    }
    cond.unlock()

    if firstCloser {
      _ = tendril_group_close(h)
      cond.lock()
      activeCalls -= 1
      cond.broadcast()
    } else {
      cond.lock()
    }

    while activeCalls > 0 {
      cond.wait()
    }
    if let toFree = handle {
      handle = nil
      cond.unlock()
      tendril_group_free(toFree)
    } else {
      cond.unlock()
    }
  }

  private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
    cond.lock()
    guard !closing, let h = handle else {
      cond.unlock()
      throw TendrilError.closed
    }
    activeCalls += 1
    cond.unlock()
    defer {
      cond.lock()
      activeCalls -= 1
      if activeCalls == 0 {
        cond.broadcast()
      }
      cond.unlock()
    }
    return try body(h)
  }

  /// Sends `data` to every reachable member and returns the `{delivered, offline, failed}` JSON.
  /// A nil `requiredCap` uses the group's default send capability.
  public func broadcast(_ data: Data, requiredCap: String? = nil) throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = try withOptionalValidatedCString(requiredCap, name: "requiredCap") { cCap in
          data.withUnsafeBytes { raw in
            tendril_group_broadcast(h, cCap, raw.bindMemory(to: UInt8.self).baseAddress, data.count, &out)
          }
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_group_broadcast failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Pushes the stored manifest (and, for an admin, the rendezvous key) to members and returns the
  /// report JSON. Wire v2 groups need it; the runtime refuses non-admins.
  public func sync() throws -> String {
    try withExpiringStateActivityIfNeeded {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = tendril_group_sync(h, &out)
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_group_sync failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// The endpoint bound by `listenAddr` at open time, or nil when none was requested.
  public func localEndpoint() throws -> String? {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_group_local_endpoint(h, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_group_local_endpoint failed")
      }
      guard out != nil else {
        return nil
      }
      return takeOutCString(out)
    }
  }

  /// Waits up to `timeoutMs` for the next event JSON (`app_data`, `manifest_updated`,
  /// `member_joined`, `member_revoked`, `audit`) and returns nil on timeout. Throws `.eof` once the
  /// pool is closed or the handle is closed while the call is waiting.
  public func pollEvent(timeoutMs: UInt64) throws -> String? {
    try withExpiringStateActivityIfNeeded(allowExpireClose: true) {
      try self.withHandle { h in
        var out: UnsafeMutablePointer<CChar>?
        let rc = tendril_group_poll_event(h, timeoutMs, &out)
        if rc == TENDRIL_WOULD_BLOCK.rawValue {
          return nil
        }
        guard rc == TENDRIL_OK.rawValue else {
          throw ffiError(rc, fallback: "tendril_group_poll_event failed")
        }
        return takeOutCString(out)
      }
    }
  }

  /// Throws unless `peerId` currently holds `cap` in the group.
  public func authorizePeer(_ peerId: String, cap: String) throws {
    try withHandle { h in
      let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
        try withValidatedCString(cap, name: "cap") { cCap in
          tendril_group_authorize_peer(h, cPeer, cCap)
        }
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_group_authorize_peer failed")
      }
    }
  }
}

import CTendril
import Foundation
#if canImport(Network)
import Network
#endif

public enum TendrilError: Error, Equatable {
  case wouldBlock
  case eof
  case invalidArgument(String)
  case closed
  case ffi(code: Int32, message: String)
}

private func lastFfiError() -> String {
  var buf = [CChar](repeating: 0, count: 512)
  let needed = buf.withUnsafeMutableBufferPointer { ptr in
    tendril_last_error(ptr.baseAddress, ptr.count)
  }
  if needed <= 1 {
    return ""
  }
  if Int(needed) <= buf.count {
    return String(cString: buf)
  }
  var larger = [CChar](repeating: 0, count: Int(needed))
  larger.withUnsafeMutableBufferPointer { ptr in
    _ = tendril_last_error(ptr.baseAddress, ptr.count)
  }
  return String(cString: larger)
}

private func ffiError(_ code: Int32, fallback: String) -> TendrilError {
  if code == TENDRIL_WOULD_BLOCK.rawValue {
    return .wouldBlock
  }
  if code == TENDRIL_EOF.rawValue {
    return .eof
  }
  let msg = lastFfiError()
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
internal final class SealedSwiftStateStore {
  private static let identityFile = "identity.sealed"
  private static let rosterFile = "roster.sealed"
  private static let bootstrapLockFile = ".identity.lock"
  private static let runtimeFiles = ["rt-roster.sealed", "rt-groups.sealed"]
  private static let identityAad = Data("tendril.identity.v1".utf8)
  private static let rosterAad = Data("tendril.roster.v1".utf8)

  private let lock = NSLock()
  private let dirUrl: URL
  private let keychain: TendrilKeychainStore

  init(dirPath: String, keychain: TendrilKeychainStore) throws {
    self.dirUrl = URL(fileURLWithPath: dirPath, isDirectory: true)
    self.keychain = keychain
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
      try fm.createDirectory(
        at: dirUrl,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    }
    try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dirUrl.path)
    // Restoring an older runtime state file would roll back group membership and revocations,
    // so the directory never enters a backup.
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var url = dirUrl
    try url.setResourceValues(values)
  }

  private func readSealed(fileName: String, aad: Data) throws -> String? {
    let url = dirUrl.appendingPathComponent(fileName, isDirectory: false)
    let fm = FileManager.default
    guard fm.fileExists(atPath: url.path) else {
      return nil
    }
    let attrs = try fm.attributesOfItem(atPath: url.path)
    if let fileType = attrs[.type] as? FileAttributeType, fileType == .typeSymbolicLink {
      throw TendrilError.invalidArgument("\(fileName) must not be a symlink")
    }
    let sealed = try Data(contentsOf: url)
    var plain = try keychain.openState(sealed, authenticating: aad)
    defer { plain.resetBytes(in: 0..<plain.count) }
    guard let s = String(data: plain, encoding: .utf8) else {
      throw TendrilKeychainError.invalidData
    }
    return s
  }

  private func writeSealed(fileName: String, json: String, aad: Data) throws {
    var plain = Data(json.utf8)
    let sealed = try {
      defer { plain.resetBytes(in: 0..<plain.count) }
      return try keychain.sealState(plain, authenticating: aad)
    }()
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
    } catch {
      try? fm.removeItem(at: tmp)
      throw error
    }
  }

  func loadIdentityJson() throws -> String? {
    lock.lock()
    defer { lock.unlock() }
    return try readSealed(fileName: Self.identityFile, aad: Self.identityAad)
  }

  func saveIdentityJson(_ json: String) throws {
    lock.lock()
    defer { lock.unlock() }
    try writeSealed(fileName: Self.identityFile, json: json, aad: Self.identityAad)
  }

  /// Reads the pre-runtime binding roster, kept only to seed a directory once.
  func loadRosterJson() throws -> String? {
    lock.lock()
    defer { lock.unlock() }
    return try readSealed(fileName: Self.rosterFile, aad: Self.rosterAad)
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
    if Darwin.unlink(path) != 0 && errno != ENOENT {
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
    return try body()
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
}

/// A Tendril endpoint. With a `stateDir`, the identity is sealed by the Keychain in
/// `identity.sealed` and the runtime persists roster and group state itself in `rt-roster.sealed`
/// and `rt-groups.sealed`, sealed under a key derived from that identity.
public final class TendrilEndpoint {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false
  /// Guards `pathMonitor`, `pathRefreshes` and `monitorClosed`. A monitor is swapped in or out
  /// with this lock held, and `start()` and `cancel()` run outside it. `close()` sets
  /// `monitorClosed` under it, so no monitor survives a close, and a monitor that was cancelled
  /// before it started refuses to start.
  private let monitorLock = NSLock()
  private var pathMonitor: TendrilPathMonitor?
  private var pathRefreshes = 0
  private var monitorClosed = false
  /// Last full transport configuration sent, as top-level JSON values. The C ABI replaces the
  /// whole configuration per call, so `configureRoutes` merges into this cache. Held across the
  /// FFI call to serialize configuration. The cache holds relay tickets and secrets, so
  /// `close()` clears it; Swift cannot zeroize the freed strings, so they linger until reused.
  private let configLock = NSLock()
  private var transportConfig: [String: Any] = [:]

  #if canImport(CryptoKit) && canImport(Security)
  public init(
    stateDir: String? = nil,
    hostId: String? = nil,
    keychainStore: TendrilKeychainStore? = nil
  ) throws {
    if let stateDir, !stateDir.isEmpty {
      let store = try SealedSwiftStateStore(
        dirPath: stateDir,
        keychain: keychainStore ?? TendrilKeychainStore()
      )
      self.handle = try store.withBootstrapLock {
        try Self.openSealed(store, stateDir: stateDir, hostId: hostId)
      }
    } else {
      let raw = try withOptionalValidatedCString(hostId, name: "hostId") { cHost in
        tendril_endpoint_new_from_state(nil, nil, cHost)
      }
      guard let raw else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new_from_state failed")
      }
      self.handle = raw
    }
  }
  #else
  public init(stateDir: String? = nil, hostId: String? = nil) throws {
    let raw = try withOptionalValidatedCString(stateDir, name: "stateDir") { cd in
      try withOptionalValidatedCString(hostId, name: "hostId") { ch in
        tendril_endpoint_new(cd, ch)
      }
    }
    guard let raw else {
      throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new failed")
    }
    self.handle = raw
  }
  #endif

  #if canImport(CryptoKit) && canImport(Security)
  private static func newSealed(
    _ stateDir: String, _ identityJson: String?, _ rosterJson: String?, _ hostId: String?
  ) throws -> OpaquePointer {
    let raw = try withValidatedCString(stateDir, name: "stateDir") { cDir in
      try withOptionalValidatedCString(identityJson, name: "identityJson") { cId in
        try withOptionalValidatedCString(rosterJson, name: "rosterJson") { cRoster in
          try withOptionalValidatedCString(hostId, name: "hostId") { cHost in
            tendril_endpoint_new_sealed(cDir, cId, cRoster, cHost)
          }
        }
      }
    }
    guard let raw else {
      throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new_sealed failed")
    }
    return raw
  }

  /// Saves a generated identity before any runtime state exists under it, then opens with it.
  /// The reopen syncs the directory, so `identity.sealed` is durable before the first runtime
  /// write, and seeds the runtime roster from a legacy `roster.sealed` only when needed.
  private static func openSealed(
    _ store: SealedSwiftStateStore, stateDir: String, hostId: String?
  ) throws -> OpaquePointer {
    var identity = try store.loadIdentityJson()
    if identity == nil {
      let fresh = try newSealed(stateDir, nil, nil, hostId)
      defer { tendril_endpoint_free(fresh) }
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_export_identity_json(fresh, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_export_identity_json failed")
      }
      let generated = takeOutCString(out)
      try store.saveIdentityJson(generated)
      identity = generated
    }
    let seed: String? = try store.legacyRosterNeedsMigration() ? store.loadRosterJson() : nil
    let raw = try newSealed(stateDir, identity, seed, hostId)
    do {
      try store.deleteLegacyRoster()
    } catch {
      tendril_endpoint_free(raw)
      throw error
    }
    return raw
  }
  #endif

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

  /// Replaces the whole transport configuration. `configureRoutes` merges into the last one sent.
  public func configureTransportsJSON(_ transportConfigJson: String) throws {
    configLock.lock()
    defer { configLock.unlock() }
    try configureTransportsLocked(transportConfigJson)
  }

  /// Sends `transportConfigJson` and caches it on success. `configLock` must be held.
  private func configureTransportsLocked(_ transportConfigJson: String) throws {
    try withHandle { h in
      let rc = try withValidatedCString(transportConfigJson, name: "transportConfigJson") { cCfg in
        tendril_endpoint_configure_transports_json(h, cCfg)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_configure_transports_json failed")
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

  public func issueCode(kind: String = "remote") throws -> String {
    try withHandle { h in
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

  public func pairInitiate(
    endpoint: String,
    relayHost: String? = nil,
    code: String,
    deviceName: String,
    deviceKind: String = "ios"
  ) throws -> String {
    try withHandle { h in
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

  public func pairAccept(timeoutMs: UInt64) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_pair_accept(h, timeoutMs, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_pair_accept failed")
      }
      return takeOutCString(out)
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
    try withHandle { h in
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

  public func pairV2Accept(timeoutMs: UInt64) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_pair_v2_accept(h, timeoutMs, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_pair_v2_accept failed")
      }
      return takeOutCString(out)
    }
  }

  public func confirmPeer(peerId: String, sas: String? = nil) throws {
    try withHandle { h in
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

  public func mintGrant(peerId: String, capsJson: String, ttlSecs: UInt64 = 3600) throws -> String {
    try withHandle { h in
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

  public func revokePeer(peerId: String) throws {
    try withHandle { h in
      let rc = try withValidatedCString(peerId, name: "peerId") { cPeer in
        tendril_endpoint_revoke_peer(h, cPeer)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_revoke_peer failed")
      }
    }
  }

  public func addTrustAnchor(anchorId: String, signingPub: Data) throws {
    guard signingPub.count == Int(TENDRIL_SIGNING_PUB_LEN) else {
      throw TendrilError.invalidArgument(
        "signingPub must be \(TENDRIL_SIGNING_PUB_LEN) bytes"
      )
    }
    try withHandle { h in
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

  public func revokeTrustAnchor(anchorId: String) throws {
    try withHandle { h in
      let rc = try withValidatedCString(anchorId, name: "anchorId") { cAnchor in
        tendril_endpoint_revoke_trust_anchor(h, cAnchor)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_endpoint_revoke_trust_anchor failed")
      }
    }
  }

  public func mintEnrollmentToken(
    targetHostId: String,
    subject: String? = nil,
    ttlSecs: UInt64 = 900
  ) throws -> String {
    try withHandle { h in
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
    return try withHandle { h in
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

  /// Opens a Wire v1 session. A `nil` or empty `endpoint` dials the peer's stored routes; a
  /// non-empty one is an explicit operator endpoint, dialed alone.
  public func connect(
    endpoint: String? = nil,
    relayHost: String? = nil,
    targetHostId: String,
    grantJson: String? = nil
  ) throws -> TendrilSession {
    try withHandle { h in
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
      return TendrilSession(handle: raw)
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
    let options = try routeOptionsJSON([
      "kind": kind, "host_name": hostName, "sign_routes": signRoutes,
    ])
    return try withHandle { h in
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
      "tendril_endpoint_pair_uri", tendril_endpoint_pair_uri, pairingUri, name, deviceKind,
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
      "tendril_endpoint_pair_v2_uri", tendril_endpoint_pair_v2_uri, pairingUri, name, deviceKind,
      routePolicy, saveRoute, endpoint, code)
  }

  private typealias PairUriFn = (
    OpaquePointer?, UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafePointer<CChar>?,
    UnsafePointer<CChar>?, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
  ) -> Int32

  private func pairUriCall(
    _ fnName: String,
    _ fn: PairUriFn,
    _ pairingUri: String,
    _ name: String?,
    _ deviceKind: String?,
    _ routePolicy: String?,
    _ saveRoute: Bool?,
    _ endpoint: String?,
    _ code: String?
  ) throws -> String {
    let options = try routeOptionsJSON([
      "route_policy": routePolicy, "save_route": saveRoute, "endpoint": endpoint, "code": code,
    ])
    return try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try withValidatedCString(pairingUri, name: "pairingUri") { cUri in
        try withOptionalValidatedCString(name, name: "name") { cName in
          try withOptionalValidatedCString(deviceKind, name: "deviceKind") { cKind in
            try withOptionalValidatedCString(options, name: "options") { cOpts in
              fn(h, cUri, cName, cKind, cOpts, &out)
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
    relayHost: String? = nil
  ) throws -> TendrilSession {
    var fields: [String: Any?] = [
      "wire": wire, "endpoint": endpoint, "recovery_uri": recoveryUri,
      "replace_routes": replaceRoutes, "route_policy": routePolicy, "relay_host": relayHost,
    ]
    if let grantJson {
      guard let obj = try? JSONSerialization.jsonObject(with: Data(grantJson.utf8)) else {
        throw TendrilError.invalidArgument("grantJson is not valid JSON")
      }
      fields["grant"] = obj
    }
    let options = try routeOptionsJSON(fields)
    return try withHandle { h in
      let raw = try withValidatedCString(targetHostId, name: "targetHostId") { cTarget in
        try withOptionalValidatedCString(options, name: "options") { cOpts in
          tendril_session_connect_with_options(h, cTarget, cOpts)
        }
      }
      guard let raw else {
        throw ffiError(
          TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_connect_with_options failed")
      }
      return TendrilSession(handle: raw)
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
    try withHandle { h in
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
    try withHandle { h in
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

  /// Applies a fresh signed pairing URI to the paired host whose keys it carries, offline.
  /// Returns `{"peer_id", "applied", "reason", "route_seq"}` as JSON.
  public func applyRouteUri(
    _ pairingUri: String,
    replaceRoutes: Bool? = nil,
    routePolicy: String? = nil
  ) throws -> String {
    let options = try routeOptionsJSON(["replace_routes": replaceRoutes, "route_policy": routePolicy])
    return try withHandle { h in
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

  /// Re-scans the host's addresses and republishes the announced route set. `nil` enumerates
  /// the interfaces natively; a snapshot is the complete network list
  /// `{"networks": [{"id", "iface", "if_index", "transports", "addrs"}]}`. Returns
  /// `{"route_seq", "changed"}` as JSON.
  @discardableResult
  public func refreshRoutes(snapshotJson: String? = nil) throws -> String {
    try withHandle { h in
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
    let routes = try routeOptions([
      "advertised_endpoints": advertisedEndpoints, "relay_auth_origins": relayAuthOrigins,
      "advertise": advertise, "route_policy": routePolicy, "sign_routes": signRoutes,
    ])
    configLock.lock()
    defer { configLock.unlock() }
    let merged = transportConfig.merging(routes) { _, new in new }
    let data = try JSONSerialization.data(withJSONObject: merged, options: [.sortedKeys])
    try configureTransportsLocked(String(decoding: data, as: UTF8.self))
  }

  private func routeOptions(_ fields: [String: Any?]) throws -> [String: Any] {
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

  private func routeOptionsJSON(_ fields: [String: Any?]) throws -> String? {
    let obj = try routeOptions(fields)
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
    monitor.start()
    previous?.cancel()
    #endif
  }

  public func stopPathMonitoring() {
    monitorLock.lock()
    let monitor = pathMonitor
    pathMonitor = nil
    monitorLock.unlock()
    monitor?.cancel()
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

  /// True while a path monitor is running.
  public var isPathMonitoring: Bool {
    monitorLock.lock()
    defer { monitorLock.unlock() }
    return pathMonitor != nil
  }

  public func acceptSession(timeoutMs: UInt64) throws -> TendrilSession {
    try withHandle { h in
      guard let raw = tendril_session_accept(h, timeoutMs) else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_accept failed")
      }
      return TendrilSession(handle: raw)
    }
  }

  /// Opens a Wire v2 session. A `nil` or empty `endpoint` dials the peer's stored routes.
  public func connectV2(
    endpoint: String? = nil,
    relayHost: String? = nil,
    targetHostId: String,
    grantJson: String? = nil
  ) throws -> TendrilSession {
    try withHandle { h in
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
      return TendrilSession(handle: raw)
    }
  }

  public func acceptV2(timeoutMs: UInt64) throws -> TendrilSession {
    try withHandle { h in
      guard let raw = tendril_session_accept_v2(h, timeoutMs) else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_accept_v2 failed")
      }
      return TendrilSession(handle: raw)
    }
  }
}

/// Calls `onChange` for every `NWPathMonitor` path update, on `queue`.
internal final class TendrilPathMonitor {
  #if canImport(Network)
  private let monitor = NWPathMonitor()
  #endif
  private let queue: DispatchQueue
  private let onChange: () -> Void
  private let lock = NSLock()
  private var cancelled = false

  init(queue: DispatchQueue, onChange: @escaping () -> Void) {
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

public final class TendrilSession {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false

  internal init(handle: OpaquePointer) {
    self.handle = handle
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
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_session_poll_event(h, timeoutMs, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_poll_event failed")
      }
      return takeOutCString(out)
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
    try withHandle { h in
      let rc = tendril_session_rekey(h)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_rekey failed")
      }
    }
  }

  public func close(code: UInt16 = 1000, reason: String = "") throws {
    try withHandle { h in
      let rc = try withValidatedCString(reason, name: "reason") { cReason in
        tendril_session_close(h, code, cReason)
      }
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_close failed")
      }
    }
  }
}

extension TendrilEndpoint {
  private func manifestCall(_ name: String, _ call: (OpaquePointer, inout UnsafeMutablePointer<CChar>?) throws -> Int32) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = try call(h, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "\(name) failed")
      }
      return takeOutCString(out)
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
    try withHandle { h in
      var raw: OpaquePointer?
      let rc = try withValidatedCString(groupId, name: "groupId") { cGroup in
        try withOptionalValidatedCString(listenAddr, name: "listenAddr") { cListen in
          tendril_group_open(h, cGroup, cListen, &raw)
        }
      }
      guard rc == TENDRIL_OK.rawValue, let raw else {
        throw ffiError(rc, fallback: "tendril_group_open failed")
      }
      return TendrilGroup(handle: raw)
    }
  }
}

public final class TendrilGroup {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false

  internal init(handle: OpaquePointer) {
    self.handle = handle
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
    try withHandle { h in
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

  /// Pushes the stored manifest (and, for an admin, the rendezvous key) to members and returns the
  /// report JSON. Wire v2 groups need it; the runtime refuses non-admins.
  public func sync() throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_group_sync(h, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_group_sync failed")
      }
      return takeOutCString(out)
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
    try withHandle { h in
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

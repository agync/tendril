import CTendril
import Foundation

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

  func loadRosterJson() throws -> String? {
    lock.lock()
    defer { lock.unlock() }
    return try readSealed(fileName: Self.rosterFile, aad: Self.rosterAad)
  }

  func saveRoster(_ exportJson: () throws -> String) throws {
    lock.lock()
    defer { lock.unlock() }
    let json = try exportJson()
    try writeSealed(fileName: Self.rosterFile, json: json, aad: Self.rosterAad)
  }
}

private func exportEndpointRosterJson(_ h: OpaquePointer) throws -> String {
  var out: UnsafeMutablePointer<CChar>?
  let rc = tendril_endpoint_export_roster_json(h, &out)
  guard rc == TENDRIL_OK.rawValue else {
    throw ffiError(rc, fallback: "tendril_endpoint_export_roster_json failed")
  }
  return takeOutCString(out)
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

public final class TendrilEndpoint {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false
  #if canImport(CryptoKit) && canImport(Security)
  private let stateStore: SealedSwiftStateStore?
  #endif

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
      let idJson = try store.loadIdentityJson()
      let rosterJson = try store.loadRosterJson()
      let raw = try withOptionalValidatedCString(idJson, name: "identityJson") { cId in
        try withOptionalValidatedCString(rosterJson, name: "rosterJson") { cRoster in
          try withOptionalValidatedCString(hostId, name: "hostId") { cHost in
            tendril_endpoint_new_from_state(cId, cRoster, cHost)
          }
        }
      }
      guard let raw else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new_from_state failed")
      }
      do {
        if idJson == nil {
          var out: UnsafeMutablePointer<CChar>?
          let rc = tendril_endpoint_export_identity_json(raw, &out)
          guard rc == TENDRIL_OK.rawValue else {
            throw ffiError(rc, fallback: "tendril_endpoint_export_identity_json failed")
          }
          try store.saveIdentityJson(takeOutCString(out))
        }
        if rosterJson == nil {
          try store.saveRoster {
            try exportEndpointRosterJson(raw)
          }
        }
      } catch {
        tendril_endpoint_free(raw)
        throw error
      }
      self.stateStore = store
      self.handle = raw
    } else {
      let raw = try withOptionalValidatedCString(hostId, name: "hostId") { cHost in
        tendril_endpoint_new_from_state(nil, nil, cHost)
      }
      guard let raw else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_endpoint_new_from_state failed")
      }
      self.stateStore = nil
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

  deinit {
    close()
  }

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

  private func persistRoster(_ h: OpaquePointer) throws {
    #if canImport(CryptoKit) && canImport(Security)
    guard let store = stateStore else { return }
    try store.saveRoster {
      try exportEndpointRosterJson(h)
    }
    #else
    _ = h
    #endif
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
      let result = takeOutCString(out)
      try persistRoster(h)
      return result
    }
  }

  public func pairAccept(timeoutMs: UInt64) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_pair_accept(h, timeoutMs, &out)
      guard rc == TENDRIL_OK.rawValue else {
        let acceptErr = ffiError(rc, fallback: "tendril_endpoint_pair_accept failed")
        if rc != TENDRIL_WOULD_BLOCK.rawValue && rc != TENDRIL_ERR_CLOSED.rawValue {
          do {
            try persistRoster(h)
          } catch {
            throw TendrilError.ffi(
              code: rc,
              message: "\(acceptErr) (roster persist error: \(error))"
            )
          }
        }
        throw acceptErr
      }
      let result = takeOutCString(out)
      try persistRoster(h)
      return result
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
      try persistRoster(h)
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
      let result = takeOutCString(out)
      try persistRoster(h)
      return result
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
      try persistRoster(h)
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
      try persistRoster(h)
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
      try persistRoster(h)
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
      let result = takeOutCString(out)
      try persistRoster(h)
      return result
    }
  }

  public func connect(
    endpoint: String,
    relayHost: String? = nil,
    targetHostId: String,
    grantJson: String? = nil
  ) throws -> TendrilSession {
    try withHandle { h in
      let raw = try withValidatedCString(endpoint, name: "endpoint") { cEp in
        try withOptionalValidatedCString(relayHost, name: "relayHost") { cRh in
          try withValidatedCString(targetHostId, name: "targetHostId") { cTarget in
            try withOptionalValidatedCString(grantJson, name: "grantJson") { cGrant in
              tendril_session_connect(h, cEp, cRh, cTarget, cGrant)
            }
          }
        }
      }
      guard let raw else {
        let connectErr = ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_connect failed")
        do {
          try persistRoster(h)
        } catch {
          throw TendrilError.ffi(
            code: TENDRIL_ERR_INTERNAL.rawValue,
            message: "\(connectErr) (roster persist error: \(error))"
          )
        }
        throw connectErr
      }
      do {
        try persistRoster(h)
      } catch {
        tendril_session_free(raw)
        throw error
      }
      #if canImport(CryptoKit) && canImport(Security)
      return TendrilSession(handle: raw, stateStore: stateStore)
      #else
      return TendrilSession(handle: raw)
      #endif
    }
  }

  public func acceptSession(timeoutMs: UInt64) throws -> TendrilSession {
    try withHandle { h in
      guard let raw = tendril_session_accept(h, timeoutMs) else {
        throw ffiError(TENDRIL_ERR_INTERNAL.rawValue, fallback: "tendril_session_accept failed")
      }
      #if canImport(CryptoKit) && canImport(Security)
      return TendrilSession(handle: raw, stateStore: stateStore)
      #else
      return TendrilSession(handle: raw)
      #endif
    }
  }
}

public final class TendrilSession {
  private let cond = NSCondition()
  private var handle: OpaquePointer?
  private var activeCalls: Int = 0
  private var closing: Bool = false
  private var lockedPersistError: Error?
  #if canImport(CryptoKit) && canImport(Security)
  private let stateStore: SealedSwiftStateStore?

  internal init(handle: OpaquePointer, stateStore: SealedSwiftStateStore? = nil) {
    self.handle = handle
    self.stateStore = stateStore
  }
  #else
  internal init(handle: OpaquePointer) {
    self.handle = handle
  }
  #endif

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
    if let err = lockedPersistError {
      cond.unlock()
      throw err
    }
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

  private func persistRoster(_ h: OpaquePointer) throws {
    #if canImport(CryptoKit) && canImport(Security)
    guard let store = stateStore else { return }
    try store.saveRoster {
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_session_export_roster_json(h, &out)
      guard rc == TENDRIL_OK.rawValue else {
        throw ffiError(rc, fallback: "tendril_session_export_roster_json failed")
      }
      return takeOutCString(out)
    }
    #else
    _ = h
    #endif
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
    var shouldFreeOnPersistFailure = false
    defer {
      if shouldFreeOnPersistFailure {
        free()
      }
    }
    return try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_session_poll_event(h, timeoutMs, &out)
      guard rc == TENDRIL_OK.rawValue else {
        if rc != TENDRIL_WOULD_BLOCK.rawValue && rc != TENDRIL_EOF.rawValue {
          do {
            try persistRoster(h)
          } catch {
            cond.lock()
            lockedPersistError = error
            cond.unlock()
            shouldFreeOnPersistFailure = true
            throw error
          }
        }
        throw ffiError(rc, fallback: "tendril_session_poll_event failed")
      }
      let ev = takeOutCString(out)
      if ev.contains("\"revocation_updated\"") {
        do {
          try persistRoster(h)
        } catch {
          cond.lock()
          lockedPersistError = error
          cond.unlock()
          shouldFreeOnPersistFailure = true
          throw error
        }
      }
      return ev
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

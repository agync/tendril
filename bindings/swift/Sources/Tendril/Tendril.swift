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
  if code == TENDRIL_WOULD_BLOCK {
    return .wouldBlock
  }
  if code == TENDRIL_EOF {
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

public enum TendrilCrypto {
  public static func deviceId(staticPub: Data) throws -> String {
    guard staticPub.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte staticPub")
    }
    var out: UnsafeMutablePointer<CChar>?
    let rc = staticPub.withUnsafeBytes { raw in
      tendril_device_id(raw.bindMemory(to: UInt8.self).baseAddress, &out)
    }
    guard rc == TENDRIL_OK else {
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
    guard rc == TENDRIL_OK else {
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
    guard rc == TENDRIL_OK else {
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
    guard rc == TENDRIL_OK else {
      throw ffiError(rc, fallback: "tendril_pairing_sas failed")
    }
    return takeOutCString(out)
  }

  public static func computeCodeMac(code: String, handshakeHash: Data) throws -> Data {
    guard handshakeHash.count == 32 else {
      throw TendrilError.invalidArgument("expected 32-byte handshakeHash")
    }
    var mac = Data(count: 32)
    let rc = code.withCString { cCode in
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
    guard rc == TENDRIL_OK else {
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
    let rc = pinnedSigningB64.withCString { cPsig in
      pinnedStaticB64.withCString { cPstat in
        chainJson.withCString { cChain in
          curStaticB64.withCString { cCstat in
            curSigningB64.withCString { cCsig in
              tendril_verify_rotation_chain_json(
                cPsig, cPstat, pinnedSeq, cChain, cCstat, cCsig, &finalSeq
              )
            }
          }
        }
      }
    }
    guard rc == TENDRIL_OK else {
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
    let rc: Int32 = grantJson.withCString { cGrant in
      issuerKeysJson.withCString { cKeys in
        expectedSubject.withCString { cSubj in
          expectedRootIssuer.withCString { cRoot in
            requestedCap.withCString { cCap in
              if let crlJson {
                return crlJson.withCString { cCrl in
                  tendril_verify_grant_json(
                    cGrant, cKeys, cSubj, cRoot, cCap, nowUnix, cCrl, &allowed
                  )
                }
              }
              return tendril_verify_grant_json(
                cGrant, cKeys, cSubj, cRoot, cCap, nowUnix, nil, &allowed
              )
            }
          }
        }
      }
    }
    guard rc == TENDRIL_OK else {
      throw ffiError(rc, fallback: "tendril_verify_grant_json failed")
    }
    return allowed == 1
  }
}

public final class TendrilEndpoint {
  private let lock = NSLock()
  private var handle: OpaquePointer?

  public init(stateDir: String? = nil, hostId: String? = nil) throws {
    let raw: OpaquePointer? = switch (stateDir, hostId) {
    case (.some(let d), .some(let h)):
      d.withCString { cd in h.withCString { ch in tendril_endpoint_new(cd, ch) } }
    case (.some(let d), .none):
      d.withCString { cd in tendril_endpoint_new(cd, nil) }
    case (.none, .some(let h)):
      h.withCString { ch in tendril_endpoint_new(nil, ch) }
    case (.none, .none):
      tendril_endpoint_new(nil, nil)
    }
    guard let raw else {
      throw ffiError(TENDRIL_ERR_INTERNAL, fallback: "tendril_endpoint_new failed")
    }
    self.handle = raw
  }

  deinit {
    close()
  }

  public func close() {
    lock.lock()
    defer { lock.unlock() }
    if let h = handle {
      handle = nil
      tendril_endpoint_free(h)
    }
  }

  private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
    lock.lock()
    defer { lock.unlock() }
    guard let h = handle else {
      throw TendrilError.closed
    }
    return try body(h)
  }

  public func infoJson() throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_info_json(h, &out)
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_info_json failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveDirect(listenAddr: String = "127.0.0.1:0") throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = listenAddr.withCString { cAddr in
        tendril_endpoint_serve_direct(h, cAddr, &out)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_direct failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveRelay(relayUrl: String, expectedHost: String? = nil) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = relayUrl.withCString { cUrl in
        if let expectedHost {
          return expectedHost.withCString { cHost in
            tendril_endpoint_serve_relay(h, cUrl, cHost, &out)
          }
        }
        return tendril_endpoint_serve_relay(h, cUrl, nil, &out)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_relay failed")
      }
      return takeOutCString(out)
    }
  }

  public func serveP2p(relayMode: String? = nil) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc: Int32
      if let relayMode {
        rc = relayMode.withCString { cMode in
          tendril_endpoint_serve_p2p(h, cMode, &out)
        }
      } else {
        rc = tendril_endpoint_serve_p2p(h, nil, &out)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_serve_p2p failed")
      }
      return takeOutCString(out)
    }
  }

  public func issueCode(kind: String = "remote") throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = kind.withCString { cKind in
        tendril_endpoint_issue_code(h, cKind, &out)
      }
      guard rc == TENDRIL_OK else {
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
      let rc = endpoint.withCString { cEp in
        code.withCString { cCode in
          deviceName.withCString { cName in
            deviceKind.withCString { cKind in
              if let relayHost {
                return relayHost.withCString { cRh in
                  tendril_endpoint_pair_initiate(h, cEp, cRh, cCode, cName, cKind, &out)
                }
              }
              return tendril_endpoint_pair_initiate(h, cEp, nil, cCode, cName, cKind, &out)
            }
          }
        }
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_pair_initiate failed")
      }
      return takeOutCString(out)
    }
  }

  public func pairAccept(timeoutMs: UInt64) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_endpoint_pair_accept(h, timeoutMs, &out)
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_pair_accept failed")
      }
      return takeOutCString(out)
    }
  }

  public func confirmPeer(peerId: String, sas: String? = nil) throws {
    try withHandle { h in
      let rc = peerId.withCString { cPeer in
        if let sas {
          return sas.withCString { cSas in tendril_endpoint_confirm_peer(h, cPeer, cSas) }
        }
        return tendril_endpoint_confirm_peer(h, cPeer, nil)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_confirm_peer failed")
      }
    }
  }

  public func mintGrant(peerId: String, capsJson: String, ttlSecs: UInt64 = 3600) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = peerId.withCString { cPeer in
        capsJson.withCString { cCaps in
          tendril_endpoint_mint_grant(h, cPeer, cCaps, ttlSecs, &out)
        }
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_mint_grant failed")
      }
      return takeOutCString(out)
    }
  }

  public func revokePeer(peerId: String) throws {
    try withHandle { h in
      let rc = peerId.withCString { cPeer in tendril_endpoint_revoke_peer(h, cPeer) }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_endpoint_revoke_peer failed")
      }
    }
  }

  public func connect(
    endpoint: String,
    relayHost: String? = nil,
    targetHostId: String,
    grantJson: String? = nil
  ) throws -> TendrilSession {
    try withHandle { h in
      let raw: OpaquePointer? = endpoint.withCString { cEp in
        targetHostId.withCString { cTarget in
          switch (relayHost, grantJson) {
          case (.some(let rh), .some(let g)):
            return rh.withCString { cr in g.withCString { cg in tendril_session_connect(h, cEp, cr, cTarget, cg) } }
          case (.some(let rh), .none):
            return rh.withCString { cr in tendril_session_connect(h, cEp, cr, cTarget, nil) }
          case (.none, .some(let g)):
            return g.withCString { cg in tendril_session_connect(h, cEp, nil, cTarget, cg) }
          case (.none, .none):
            return tendril_session_connect(h, cEp, nil, cTarget, nil)
          }
        }
      }
      guard let raw else {
        throw ffiError(TENDRIL_ERR_INTERNAL, fallback: "tendril_session_connect failed")
      }
      return TendrilSession(handle: raw)
    }
  }

  public func acceptSession(timeoutMs: UInt64) throws -> TendrilSession {
    try withHandle { h in
      guard let raw = tendril_session_accept(h, timeoutMs) else {
        throw ffiError(TENDRIL_ERR_INTERNAL, fallback: "tendril_session_accept failed")
      }
      return TendrilSession(handle: raw)
    }
  }
}

public final class TendrilSession {
  private let lock = NSLock()
  private var handle: OpaquePointer?

  internal init(handle: OpaquePointer) {
    self.handle = handle
  }

  deinit {
    free()
  }

  public func free() {
    lock.lock()
    defer { lock.unlock() }
    if let h = handle {
      handle = nil
      tendril_session_free(h)
    }
  }

  private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
    lock.lock()
    defer { lock.unlock() }
    guard let h = handle else {
      throw TendrilError.closed
    }
    return try body(h)
  }

  public func sendData(_ data: Data) throws {
    try withHandle { h in
      let rc = data.withUnsafeBytes { raw in
        tendril_session_send_data(h, raw.bindMemory(to: UInt8.self).baseAddress, data.count)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_session_send_data failed")
      }
    }
  }

  public func pollEvent(timeoutMs: UInt64) throws -> String {
    try withHandle { h in
      var out: UnsafeMutablePointer<CChar>?
      let rc = tendril_session_poll_event(h, timeoutMs, &out)
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_session_poll_event failed")
      }
      return takeOutCString(out)
    }
  }

  public func authorize(_ requestedCap: String) throws -> Bool {
    try withHandle { h in
      var allowed: UInt8 = 0
      let rc = requestedCap.withCString { cCap in
        tendril_session_authorize(h, cCap, &allowed)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_session_authorize failed")
      }
      return allowed == 1
    }
  }

  public func rekey() throws {
    try withHandle { h in
      let rc = tendril_session_rekey(h)
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_session_rekey failed")
      }
    }
  }

  public func close(code: UInt16 = 1000, reason: String = "") throws {
    try withHandle { h in
      let rc = reason.withCString { cReason in
        tendril_session_close(h, code, cReason)
      }
      guard rc == TENDRIL_OK else {
        throw ffiError(rc, fallback: "tendril_session_close failed")
      }
    }
  }
}

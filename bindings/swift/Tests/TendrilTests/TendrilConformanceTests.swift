import Dispatch
import Foundation
#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security
#endif
import Testing
@testable import Tendril

private final class SendableBox<T>: @unchecked Sendable {
  private let lock = NSLock()
  private var value: T

  init(_ value: T) {
    self.value = value
  }

  func set(_ newValue: T) {
    lock.lock()
    defer { lock.unlock() }
    value = newValue
  }

  func get() -> T {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

@Suite
struct TendrilConformanceTests {
  private func vectorsDir() -> URL {
    let fileUrl = URL(fileURLWithPath: #filePath)
    return fileUrl
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("spec")
      .appendingPathComponent("vectors")
  }

  private func loadJson(_ name: String) throws -> [String: Any] {
    let data = try Data(contentsOf: vectorsDir().appendingPathComponent(name))
    let obj = try JSONSerialization.jsonObject(with: data)
    return obj as! [String: Any]
  }

  private func hexData(_ hex: String) -> Data {
    var out = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
      let next = hex.index(idx, offsetBy: 2)
      let byte = UInt8(hex[idx..<next], radix: 16)!
      out.append(byte)
      idx = next
    }
    return out
  }

  private func b64Url(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  @Test
  func conformanceVectors() throws {
    let fp = try loadJson("fingerprints.json")
    let rawPub = hexData(fp["raw_pubkey_hex"] as! String)
    let hh = hexData(fp["handshake_hash_hex"] as! String)
    #expect(try TendrilCrypto.deviceId(staticPub: rawPub) == (fp["raw_device_id"] as? String))
    #expect(
      try TendrilCrypto.fingerprintHost(staticPub: rawPub) == (fp["raw_host_fingerprint"] as? String)
    )
    #expect(
      try TendrilCrypto.fingerprintDevice(staticPub: rawPub) == (fp["raw_device_fingerprint"] as? String)
    )
    #expect(try TendrilCrypto.pairingSas(handshakeHash: hh) == (fp["pairing_sas"] as? String))

    let pm = try loadJson("pairing_mac.json")
    let pmHh = hexData(pm["handshake_hash_hex"] as! String)
    let r3 = pm["remote_3group"] as! [String: Any]
    #expect(
      try TendrilCrypto.computeCodeMac(code: r3["code"] as! String, handshakeHash: pmHh)
        == hexData(r3["code_mac_hex"] as! String)
    )

    let rot = try loadJson("rotation.json")
    let pSig = b64Url(hexData(rot["pinned_signing_pub_hex"] as! String))
    let pStat = b64Url(hexData(rot["pinned_static_pub_hex"] as! String))
    let chainItems = rot["chain"] as! [[String: Any]]
    let records = chainItems.map { $0["record"] as! [String: Any] }
    let chainJson = String(data: try JSONSerialization.data(withJSONObject: records), encoding: .utf8)!
    let lastRec = records.last!
    let finalSeq = try TendrilCrypto.verifyRotationChainJson(
      pinnedSigningB64: pSig,
      pinnedStaticB64: pStat,
      pinnedSeq: 0,
      chainJson: chainJson,
      curStaticB64: lastRec["new_static_pub"] as! String,
      curSigningB64: lastRec["new_signing_pub"] as! String
    )
    #expect(finalSeq == 2)

    let forkEntry = (rot["fork_record"] as! [String: Any])["record"] as! [String: Any]
    let forkJson = String(
      data: try JSONSerialization.data(withJSONObject: [records[0], forkEntry]),
      encoding: .utf8
    )!
    #expect(throws: Error.self) {
      _ = try TendrilCrypto.verifyRotationChainJson(
        pinnedSigningB64: pSig,
        pinnedStaticB64: pStat,
        pinnedSeq: 0,
        chainJson: forkJson,
        curStaticB64: lastRec["new_static_pub"] as! String,
        curSigningB64: lastRec["new_signing_pub"] as! String
      )
    }

    let gv = try loadJson("grants.json")
    let keys: [String: String] = [
      gv["root_issuer_id"] as! String: b64Url(hexData(gv["root_signing_pub_hex"] as! String)),
      gv["delegate_id"] as! String: b64Url(hexData(gv["delegate_signing_pub_hex"] as! String)),
    ]
    let keysJson = String(data: try JSONSerialization.data(withJSONObject: keys), encoding: .utf8)!
    let validJson = String(
      data: try JSONSerialization.data(withJSONObject: gv["delegated_valid"]!),
      encoding: .utf8
    )!
    let widenedJson = String(
      data: try JSONSerialization.data(withJSONObject: gv["delegated_widened"]!),
      encoding: .utf8
    )!
    let leafId = gv["leaf_id"] as! String
    let rootId = gv["root_issuer_id"] as! String
    #expect(
      try TendrilCrypto.verifyGrantJson(
        grantJson: validJson,
        issuerKeysJson: keysJson,
        expectedSubject: leafId,
        expectedRootIssuer: rootId,
        requestedCap: "fs.read:/photos/2026/a.jpg",
        nowUnix: 1795564800
      )
    )
    #expect(
      !(try TendrilCrypto.verifyGrantJson(
        grantJson: widenedJson,
        issuerKeysJson: keysJson,
        expectedSubject: leafId,
        expectedRootIssuer: rootId,
        requestedCap: "fs.read:/photos/2026/a.jpg",
        nowUnix: 1795564800
      ))
    )
  }

  @Test
  func localEndpointLifecycle() throws {
    let host = try TendrilEndpoint(hostId: "swift-host")
    let client = try TendrilEndpoint(hostId: "swift-client")
    defer {
      host.close()
      client.close()
    }

    let addr = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let code = try host.issueCode(kind: "lan")

    let pairQueue = DispatchQueue(label: "tendril.swift.pair")
    let pairSem = DispatchSemaphore(value: 0)
    let acceptBox = SendableBox<String>("")
    pairQueue.async {
      acceptBox.set((try? host.pairAccept(timeoutMs: 5000)) ?? "")
      pairSem.signal()
    }
    let initJson = try client.pairInitiate(endpoint: addr, code: code, deviceName: "swift-phone", deviceKind: "ios")
    #expect(pairSem.wait(timeout: .now() + 5.0) == .success)

    let initObj = try JSONSerialization.jsonObject(with: Data(initJson.utf8)) as! [String: Any]
    let accObj = try JSONSerialization.jsonObject(with: Data(acceptBox.get().utf8)) as! [String: Any]
    #expect(initObj["sas"] as? String == accObj["sas"] as? String)
    let devId = accObj["device_id"] as! String

    try host.confirmPeer(peerId: devId, sas: accObj["sas"] as? String)
    try client.confirmPeer(peerId: "swift-host", sas: initObj["sas"] as? String)
    let grantJson = try host.mintGrant(peerId: devId, capsJson: "[\"fs.read\"]", ttlSecs: 3600)

    let sessSem = DispatchSemaphore(value: 0)
    let sessBox = SendableBox<TendrilSession?>(nil)
    pairQueue.async {
      sessBox.set(try? host.acceptSession(timeoutMs: 5000))
      sessSem.signal()
    }
    let cliSess = try client.connect(endpoint: addr, targetHostId: "swift-host", grantJson: grantJson)
    #expect(sessSem.wait(timeout: .now() + 5.0) == .success)
    let srvSess = try #require(sessBox.get())
    defer {
      cliSess.free()
      srvSess.free()
    }

    #expect(try srvSess.authorize("fs.read"))
    #expect(!(try srvSess.authorize("shell.exec")))
    try cliSess.sendData(Data("hello-swift".utf8))
    let evJson = try srvSess.pollEvent(timeoutMs: 2000)
    let evObj = try JSONSerialization.jsonObject(with: Data(evJson.utf8)) as! [String: Any]
    #expect(evObj["event"] as? String == "data")
    try host.revokePeer(peerId: devId)
    #expect(!(try srvSess.authorize("fs.read")))
    try cliSess.close(code: 1000, reason: "done")
  }

  @Test
  func m2mEnrollmentAndReplay() throws {
    let host = try TendrilEndpoint(hostId: "swift-m2m-host")
    let anchor = try TendrilEndpoint(hostId: "swift-m2m-anchor")
    let client = try TendrilEndpoint(hostId: "swift-m2m-cli")
    defer {
      client.close()
      anchor.close()
      host.close()
    }

    func decodeB64Url(_ s: String) -> Data {
      var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
      while b64.count % 4 != 0 { b64.append("=") }
      return Data(base64Encoded: b64)!
    }

    let hostInfo = try JSONSerialization.jsonObject(with: Data(host.infoJson().utf8)) as! [String: Any]
    let anchorInfo = try JSONSerialization.jsonObject(with: Data(anchor.infoJson().utf8)) as! [String: Any]
    let hostStatic = decodeB64Url(hostInfo["static_pub"] as! String)
    let hostSigning = decodeB64Url(hostInfo["signing_pub"] as! String)
    let hostSigningHash = decodeB64Url(hostInfo["signing_pub_hash"] as! String)
    let anchorSigning = decodeB64Url(anchorInfo["signing_pub"] as! String)
    #expect(hostSigning.count == 1984)
    #expect(hostSigningHash.count == 32)
    #expect(anchorSigning.count == 1984)

    try host.addTrustAnchor(anchorId: "swift-m2m-anchor", signingPub: anchorSigning)
    let addr = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let tokJson = try anchor.mintEnrollmentToken(targetHostId: "swift-m2m-host", subject: nil, ttlSecs: 900)

    let queue = DispatchQueue(label: "tendril.swift.m2m")
    let pairSem = DispatchSemaphore(value: 0)
    let accBox = SendableBox<String>("")
    queue.async {
      accBox.set((try? host.pairAccept(timeoutMs: 5000)) ?? "")
      pairSem.signal()
    }
    let initJson = try client.enrollInitiate(
      endpoint: addr,
      hostId: "swift-m2m-host",
      hostStaticPub: hostStatic,
      hostSigningPub: hostSigning,
      tokenJson: tokJson
    )
    #expect(pairSem.wait(timeout: .now() + 5.0) == .success)
    let initObj = try JSONSerialization.jsonObject(with: Data(initJson.utf8)) as! [String: Any]
    let accObj = try JSONSerialization.jsonObject(with: Data(accBox.get().utf8)) as! [String: Any]
    #expect(initObj["status"] as? String == "active")
    #expect(accObj["status"] as? String == "active")

    let repSem = DispatchSemaphore(value: 0)
    queue.async {
      _ = try? host.pairAccept(timeoutMs: 5000)
      repSem.signal()
    }
    #expect(throws: Error.self) {
      _ = try client.enrollInitiate(
        endpoint: addr,
        hostId: "swift-m2m-host",
        hostStaticPub: hostStatic,
        hostSigningPub: hostSigningHash,
        tokenJson: tokJson
      )
    }
    #expect(repSem.wait(timeout: .now() + 5.0) == .success)
  }

  @Test
  func keychainSealedStateRoundtrip() throws {
    let tmpDir = FileManager.default.temporaryDirectory
      .appendingPathComponent("tendril-swift-kc-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: tmpDir) }

    let service = "dev.tendril.state.test"
    let account = "test-\(UUID().uuidString)"
    #if canImport(CryptoKit) && canImport(Security)
    let realKc = TendrilKeychainStore(service: service, account: account)
    defer {
      let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
      ]
      SecItemDelete(query as CFDictionary)
    }
    let kc: TendrilKeychainStore
    do {
      _ = try realKc.loadOrCreateMasterKey()
      kc = realKc
    } catch TendrilKeychainError.osStatus(let status)
      where status == errSecWrPerm || status == errSecInteractionNotAllowed || status == -34018
    {
      print("[TendrilTests] NOTICE: live Keychain unavailable in headless CLI (OSStatus \(status)); testing sealed state via @testable seam")
      let testKey = SymmetricKey(size: .bits256)
      kc = TendrilKeychainStore(service: service, account: account) { testKey }
    }

    let ep1 = try TendrilEndpoint(stateDir: tmpDir.path, hostId: "swift-kc-host", keychainStore: kc)
    let info1 = try ep1.infoJson()
    ep1.close()

    let ep2 = try TendrilEndpoint(stateDir: tmpDir.path, hostId: "swift-kc-host", keychainStore: kc)
    let info2 = try ep2.infoJson()
    ep2.close()

    // Deterministic AES-GCM seal/open + tamper rejection via @testable seam.
    let seamKey = SymmetricKey(size: .bits256)
    let seamKc = TendrilKeychainStore(service: service, account: account) { seamKey }
    let aad = Data("tendril.test.aad".utf8)
    let plaintext = Data("tendril-secret-state".utf8)
    let sealed = try seamKc.sealState(plaintext, authenticating: aad)
    #expect(try seamKc.openState(sealed, authenticating: aad) == plaintext)
    #expect(throws: Error.self) {
      _ = try seamKc.openState(sealed, authenticating: Data("wrong-aad".utf8))
    }
    var tampered = sealed
    tampered[tampered.count - 1] ^= 0xFF
    #expect(throws: Error.self) {
      _ = try seamKc.openState(tampered, authenticating: aad)
    }
    #else
    let ep1 = try TendrilEndpoint(stateDir: tmpDir.path, hostId: "swift-kc-host")
    let info1 = try ep1.infoJson()
    ep1.close()

    let ep2 = try TendrilEndpoint(stateDir: tmpDir.path, hostId: "swift-kc-host")
    let info2 = try ep2.infoJson()
    ep2.close()
    #endif

    let obj1 = try JSONSerialization.jsonObject(with: Data(info1.utf8)) as! [String: Any]
    let obj2 = try JSONSerialization.jsonObject(with: Data(info2.utf8)) as! [String: Any]
    #expect(obj1["static_pub"] as? String == obj2["static_pub"] as? String)
    #expect(obj1["signing_pub"] as? String == obj2["signing_pub"] as? String)
  }
}

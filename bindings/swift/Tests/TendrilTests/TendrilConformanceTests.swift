import Dispatch
import Foundation
#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security
#endif
#if canImport(CoreImage) && canImport(Vision) && os(macOS)
import CoreImage
import Vision
#endif
import Testing
import CTendril
@testable import Tendril

/// Runs the blocking peer side of a test on its own thread. A synchronous test body holds a
/// Swift concurrency cooperative thread while it waits, and the pool has one thread per CPU:
/// once every one is blocked, `DispatchQueue.global()` work is not started, so the peer never
/// answers and the test times out.
private func onDedicatedThread(_ body: @escaping @Sendable () -> Void) {
  Thread(block: body).start()
}

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

    #expect(try cliSess.peerId() == "swift-host")
    #expect(try srvSess.peerId() == devId)
    #expect(try srvSess.authorize("fs.read"))
    #expect(!(try srvSess.authorize("shell.exec")))
    try cliSess.sendData(Data("hello-swift".utf8))
    let evJson = try srvSess.pollEvent(timeoutMs: 2000)
    let evObj = try JSONSerialization.jsonObject(with: Data(evJson.utf8)) as! [String: Any]
    #expect(evObj["event"] as? String == "data")
    try host.revokePeer(peerId: devId)
    #expect(try srvSess.peerId() == devId)
    #expect(!(try srvSess.authorize("fs.read")))
    try cliSess.close(code: 1000, reason: "done")
    cliSess.free()
    #expect(throws: TendrilError.closed) { _ = try cliSess.peerId() }
  }

  @Test
  func groupApisRefuseEndpointsWithoutStateDirectory() throws {
    let ep = try TendrilEndpoint(hostId: "swift-group-refused")
    defer { ep.close() }
    #expect(throws: Error.self) {
      _ = try ep.groupCreate(name: "swift-group")
    }
    #expect(throws: Error.self) {
      _ = try ep.groupAddMember(groupId: "grp_none", peerId: "dev_none")
    }
    #expect(throws: Error.self) {
      _ = try ep.groupRemoveMember(groupId: "grp_none", peerId: "dev_none")
    }
    #expect(throws: Error.self) {
      _ = try ep.groupIngestManifest(manifestJson: "{}", senderPeerId: "dev_none")
    }
    #expect(throws: Error.self) {
      _ = try ep.openGroup(groupId: "grp_none")
    }
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

    let clientDevId = try #require(initObj["device_id"] as? String)
    let grantJson = try host.mintGrant(peerId: clientDevId, capsJson: "[\"fs.read\"]", ttlSecs: 3600)
    let sessSem = DispatchSemaphore(value: 0)
    let hostSessBox = SendableBox<TendrilSession?>(nil)
    queue.async {
      hostSessBox.set(try? host.acceptSession(timeoutMs: 5000))
      sessSem.signal()
    }
    let cliSess = try client.connect(endpoint: addr, targetHostId: "swift-m2m-host", grantJson: grantJson)
    defer { cliSess.free() }
    #expect(sessSem.wait(timeout: .now() + 5.0) == .success)
    let hostSess = try #require(hostSessBox.get())
    defer { hostSess.free() }
    #expect(try hostSess.authorize("fs.read"))
    #expect(try !hostSess.authorize("shell.exec"))
    #expect(try cliSess.peerId() == "swift-m2m-host")
    #expect(try hostSess.peerId() == clientDevId)
    try cliSess.close()
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
      for (suffix, isSepOrV2) in [
        ("", false),
        (TendrilKeychainStore.sepP256AccountSuffix, true),
        (TendrilKeychainStore.v2CommittedAccountSuffix, true),
        (".sep-mldsa65", true),
      ] {
        SecItemDelete(
          realKc.keychainQueryBase(accountSuffix: suffix, isSepOrV2: isSepOrV2) as CFDictionary
        )
      }
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

  #if canImport(CryptoKit) && canImport(Security)
  @Test
  func keychainSealedEndpointHostsGroupAcrossRestart() throws {
    let fm = FileManager.default
    let rootDir = fm.temporaryDirectory.appendingPathComponent("tendril-swift-grp-a-\(UUID().uuidString)")
    let memberDir = fm.temporaryDirectory.appendingPathComponent("tendril-swift-grp-b-\(UUID().uuidString)")
    defer {
      try? fm.removeItem(at: rootDir)
      try? fm.removeItem(at: memberDir)
    }
    let rootKey = SymmetricKey(size: .bits256)
    let memberKey = SymmetricKey(size: .bits256)
    let rootKc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "grp-a") { rootKey }
    let memberKc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "grp-b") { memberKey }

    func decodeB64Url(_ s: String) -> Data {
      var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
      while b64.count % 4 != 0 { b64.append("=") }
      return Data(base64Encoded: b64)!
    }
    func object(_ json: String) throws -> [String: Any] {
      try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    }
    func broadcastUntilDelivered(_ group: TendrilGroup, _ payload: String) throws -> [String: Any] {
      let deadline = Date().addingTimeInterval(15)
      while true {
        let report = try object(group.broadcast(Data(payload.utf8)))
        if (report["delivered"] as? [Any])?.count == 1 || Date() > deadline {
          return report
        }
        Thread.sleep(forTimeInterval: 0.2)
      }
    }
    func waitAppData(_ group: TendrilGroup) throws -> [String: Any] {
      let deadline = Date().addingTimeInterval(15)
      while Date() < deadline {
        guard let raw = try group.pollEvent(timeoutMs: 500) else { continue }
        let ev = try object(raw)
        if ev["event"] as? String == "app_data" {
          return ev
        }
      }
      throw TendrilError.invalidArgument("no app_data event in time")
    }

    let root = try TendrilEndpoint(stateDir: rootDir.path, keychainStore: rootKc)
    defer { root.close() }
    let rootInfo = try object(root.infoJson())
    let rootId = rootInfo["device_id"] as! String
    let rootAddr = try root.serveDirect(listenAddr: "127.0.0.1:0")

    var member = try TendrilEndpoint(stateDir: memberDir.path, keychainStore: memberKc)
    let memberInfo = try object(member.infoJson())
    let memberId = memberInfo["device_id"] as! String
    let token = try root.mintEnrollmentToken(targetHostId: rootId, subject: memberId, ttlSecs: 300)
    let queue = DispatchQueue(label: "tendril.swift.sealed-group")
    let acceptSem = DispatchSemaphore(value: 0)
    queue.async {
      _ = try? root.pairAccept(timeoutMs: 10_000)
      acceptSem.signal()
    }
    _ = try member.enrollInitiate(
      endpoint: rootAddr,
      hostId: rootId,
      hostStaticPub: decodeB64Url(rootInfo["static_pub"] as! String),
      hostSigningPub: decodeB64Url(rootInfo["signing_pub"] as! String),
      tokenJson: token
    )
    #expect(acceptSem.wait(timeout: .now() + 10.0) == .success)

    let created = try object(root.groupCreate(name: "swift-sealed", endpointsJson: "[\"\(rootAddr)\"]"))
    let gid = created["group_id"] as! String
    let manifest = try root.groupAddMember(groupId: gid, peerId: memberId)
    #expect(try member.groupIngestManifest(manifestJson: manifest, senderPeerId: rootId) == gid)

    let rootGroup = try root.openGroup(groupId: gid)
    defer { rootGroup.close() }
    let first = try member.openGroup(groupId: gid)
    #expect((try broadcastUntilDelivered(first, "before")["delivered"] as? [Any])?.count == 1)
    #expect(try waitAppData(rootGroup)["sender_device_id"] as? String == memberId)
    first.close()
    member.close()

    for name in ["rt-groups.sealed", "rt-roster.sealed", "identity.sealed"] {
      #expect(fm.fileExists(atPath: memberDir.appendingPathComponent(name).path), "\(name)")
    }
    for name in ["groups.json", "roster.json", "roster.sealed"] {
      #expect(!fm.fileExists(atPath: memberDir.appendingPathComponent(name).path), "\(name)")
    }
    let excluded = try memberDir.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
    #expect(excluded == true)

    member = try TendrilEndpoint(stateDir: memberDir.path, keychainStore: memberKc)
    let second = try member.openGroup(groupId: gid)
    #expect((try broadcastUntilDelivered(second, "after")["delivered"] as? [Any])?.count == 1)
    let ev = try waitAppData(rootGroup)
    #expect(ev["sender_device_id"] as? String == memberId)
    #expect(decodeB64Url(ev["payload_b64"] as! String) == Data("after".utf8))
    second.close()
    member.close()

    let groupsUrl = memberDir.appendingPathComponent("rt-groups.sealed")
    var tampered = try Data(contentsOf: groupsUrl)
    tampered[tampered.count - 1] ^= 0x01
    try tampered.write(to: groupsUrl)
    #expect(throws: Error.self) {
      _ = try TendrilEndpoint(stateDir: memberDir.path, keychainStore: memberKc)
    }
  }
  #endif

  #if canImport(CryptoKit) && canImport(Security)
  private func jsonObject(_ json: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
  }

  private func sealedRosterJson(_ dir: URL, _ identityJson: String) throws -> String {
    let ep = dir.path.withCString { cDir in
      identityJson.withCString { cId in tendril_endpoint_new_sealed(cDir, cId, nil, nil) }
    }
    guard let ep else {
      throw TendrilError.invalidArgument("tendril_endpoint_new_sealed failed")
    }
    defer { tendril_endpoint_free(ep) }
    var out: UnsafeMutablePointer<CChar>?
    guard tendril_endpoint_export_roster_json(ep, &out) == TENDRIL_OK.rawValue, let out else {
      throw TendrilError.invalidArgument("tendril_endpoint_export_roster_json failed")
    }
    defer { tendril_string_free(out) }
    return String(cString: out)
  }

  @Test
  func keychainSealedEndpointMigratesLegacyRosterOnce() throws {
    let fm = FileManager.default
    let base = fm.temporaryDirectory.appendingPathComponent("tendril-swift-mig-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: base) }
    let rootDir = base.appendingPathComponent("a")
    let memberDir = base.appendingPathComponent("b")
    let legacyDir = base.appendingPathComponent("c")
    let rootKey = SymmetricKey(size: .bits256)
    let memberKey = SymmetricKey(size: .bits256)
    let rootKc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "mig-a") { rootKey }
    let memberKc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "mig-b") { memberKey }
    func decodeB64Url(_ s: String) -> Data {
      var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
      while b64.count % 4 != 0 { b64.append("=") }
      return Data(base64Encoded: b64)!
    }

    let root = try TendrilEndpoint(stateDir: rootDir.path, keychainStore: rootKc)
    defer { root.close() }
    let rootInfo = try jsonObject(root.infoJson())
    let rootHostId = rootInfo["host_id"] as! String
    let rootAddr = try root.serveDirect(listenAddr: "127.0.0.1:0")
    let member = try TendrilEndpoint(stateDir: memberDir.path, keychainStore: memberKc)
    let memberId = try jsonObject(member.infoJson())["device_id"] as! String
    let token = try root.mintEnrollmentToken(targetHostId: rootHostId, subject: memberId, ttlSecs: 300)
    let acceptSem = DispatchSemaphore(value: 0)
    DispatchQueue(label: "tendril.swift.migrate").async {
      _ = try? root.pairAccept(timeoutMs: 10_000)
      acceptSem.signal()
    }
    _ = try member.enrollInitiate(
      endpoint: rootAddr,
      hostId: rootHostId,
      hostStaticPub: decodeB64Url(rootInfo["static_pub"] as! String),
      hostSigningPub: decodeB64Url(rootInfo["signing_pub"] as! String),
      tokenJson: token
    )
    #expect(acceptSem.wait(timeout: .now() + 10.0) == .success)
    member.close()

    let identityJson = try #require(
      try SealedSwiftStateStore(dirPath: memberDir.path, keychain: memberKc).loadIdentityJson()
    )
    func hasRoot(_ rosterJson: String) throws -> Bool {
      (try jsonObject(rosterJson)["entries"] as? [String: Any])?[rootHostId] != nil
    }
    let rosterJson = try sealedRosterJson(memberDir, identityJson)
    #expect(try hasRoot(rosterJson))

    // A pre-runtime binding directory: identity plus a nonempty binding-sealed roster.
    try SealedSwiftStateStore(dirPath: legacyDir.path, keychain: memberKc).saveIdentityJson(identityJson)
    let legacy = legacyDir.appendingPathComponent("roster.sealed")
    try memberKc.sealState(Data(rosterJson.utf8), authenticating: Data("tendril.roster.v1".utf8))
      .write(to: legacy)
    let migrated = try TendrilEndpoint(stateDir: legacyDir.path, keychainStore: memberKc)
    #expect(try jsonObject(migrated.infoJson())["device_id"] as? String == memberId)
    migrated.close()
    #expect(!fm.fileExists(atPath: legacy.path))
    #expect(fm.fileExists(atPath: legacyDir.appendingPathComponent("rt-roster.sealed").path))
    #expect(try hasRoot(sealedRosterJson(legacyDir, identityJson)))

    // Cleanup interrupted after migration: the leftover is deleted unread, even if corrupt.
    try Data([1, 2, 3]).write(to: legacy)
    try TendrilEndpoint(stateDir: legacyDir.path, keychainStore: memberKc).close()
    #expect(!fm.fileExists(atPath: legacy.path))
    #expect(try hasRoot(sealedRosterJson(legacyDir, identityJson)))
  }

  @Test
  func keychainConcurrentFirstOpensShareOneIdentity() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("tendril-swift-race-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: dir) }
    let key = SymmetricKey(size: .bits256)
    let kc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "race") { key }

    let lock = NSLock()
    var ids: [String] = []
    DispatchQueue.concurrentPerform(iterations: 4) { _ in
      let id: String
      do {
        let ep = try TendrilEndpoint(stateDir: dir.path, keychainStore: kc)
        defer { ep.close() }
        id = try jsonObject(ep.infoJson())["device_id"] as! String
      } catch {
        id = "error: \(error)"
      }
      lock.lock()
      ids.append(id)
      lock.unlock()
    }
    #expect(ids.count == 4)
    #expect(Set(ids).count == 1, "\(ids)")
    let again = try TendrilEndpoint(stateDir: dir.path, keychainStore: kc)
    defer { again.close() }
    #expect(try jsonObject(again.infoJson())["device_id"] as? String == ids.first)
  }
  #endif

  @Test
  func configureTransportsJSONValidation() throws {
    let ep = try TendrilEndpoint(stateDir: nil, hostId: "swift-cfg-ep")
    defer { ep.close() }

    try ep.configureTransportsJSON("{}")

    let secretSentinel = "swift-secret-sentinel-888"
    do {
      try ep.configureTransportsJSON(
        "{\"relay_auth_secret\":\"\(secretSentinel)\",\"unknown_field\":true}"
      )
      Issue.record("expected unknown_field to fail")
    } catch {
      #expect(!String(describing: error).contains(secretSentinel))
    }

    do {
      try ep.configureTransportsJSON("{\"relay_auth_secret\":98765}")
      Issue.record("expected scalar mismatch to fail")
    } catch {
      #expect(!String(describing: error).contains("98765"))
    }

    #expect(throws: Error.self) {
      try ep.configureTransportsJSON("{\u{0}}")
    }
  }

  #if os(macOS) || os(Linux)
  private func repoRoot() -> URL {
    vectorsDir().deletingLastPathComponent().deletingLastPathComponent()
  }

  private func stripAnsi(_ s: String) -> String {
    s.replacingOccurrences(of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
  }

  private func startRelay(extraEnv: [String: String] = [:], args: [String] = []) throws -> (Process, String, String) {
    let bin = repoRoot().appendingPathComponent("target/debug/tendril-relay")
    let proc = Process()
    proc.executableURL = bin
    proc.arguments = ["--listen", "127.0.0.1:0", "--host", "127.0.0.1"] + args
    var env = ProcessInfo.processInfo.environment
    env["RUST_LOG"] = "info"
    for (k, v) in extraEnv {
      env[k] = v
    }
    proc.environment = env

    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = pipe
    try proc.run()

    let handle = pipe.fileHandleForReading
    let box = SendableBox<String?>(nil)
    let logBox = SendableBox<String>("")
    let sem = DispatchSemaphore(value: 0)

    onDedicatedThread {
      while true {
        let data = handle.availableData
        if data.isEmpty { break }
        if let chunk = String(data: data, encoding: .utf8) {
          let clean = stripAnsi(chunk)
          let combined = logBox.get() + clean
          logBox.set(combined)
          if box.get() == nil {
            for line in combined.split(separator: "\n") {
              if let r = line.range(of: "ws://127.0.0.1:") {
                let rest = String(line[r.lowerBound...])
                let tok = String(rest.prefix { $0 != " " && $0 != "\t" && $0 != "\r" && $0 != "\"" })
                if tok.hasSuffix("/v1/relay") {
                  box.set(tok)
                  sem.signal()
                  break
                }
              }
            }
          }
        }
      }
    }

    guard sem.wait(timeout: .now() + 10.0) == .success, let v1Url = box.get() else {
      proc.terminate()
      throw TendrilError.ffi(code: -7, message: "tendril-relay startup failed: \(logBox.get())")
    }
    let v2Url = String(v1Url.dropLast("/v1/relay".count)) + "/v2/relay"
    return (proc, v1Url, v2Url)
  }

  @Test
  func configureRoutesKeepsRelayTicket() throws {
    let issuer = try TendrilEndpoint(stateDir: nil, hostId: "swift-routes-issuer")
    defer { issuer.close() }
    let issuerInfo = try JSONSerialization.jsonObject(with: Data(issuer.infoJson().utf8)) as! [String: Any]
    let issuerPub = try #require(issuerInfo["relay_pub"] as? String)
    let regTicket = try issuer.mintRelayTicket(
      relayHost: "127.0.0.1", role: "register", targetPubOrWildcard: "*", ttlSecs: 300)
    let (relayProc, v1Url, _) = try startRelay(args: ["--issuer-pub", issuerPub, "--auth-scope", "all"])
    defer {
      relayProc.terminate()
      relayProc.waitUntilExit()
    }
    let host = try TendrilEndpoint(stateDir: nil, hostId: "swift-routes-ticket-host")
    defer { host.close() }
    try host.configureTransportsJSON("{\"relay_ticket\":\(regTicket)}")
    try host.configureRoutes(routePolicy: "committed_only")
    _ = try host.serveRelay(relayUrl: v1Url, expectedHost: "127.0.0.1")

    // A no-argument call re-sends the cached configuration instead of resetting it.
    try host.configureRoutes()
    _ = try host.serveRelay(relayUrl: v1Url, expectedHost: "127.0.0.1")

    // A full replacement updates the cache, so a later configureRoutes does not restore the ticket.
    try host.configureTransportsJSON("{}")
    try host.configureRoutes(routePolicy: "all_signed")
    #expect(throws: Error.self) {
      _ = try host.serveRelay(relayUrl: v1Url, expectedHost: "127.0.0.1")
    }
  }

  @Test
  func relayAdmissionHMACAndTickets() throws {
    let hmacSecret = "swift-shared-relay-hmac-secret"
    let (relayProc, v1Url, v2Url) = try startRelay(
      extraEnv: ["TENDRIL_RELAY_AUTH_SECRET": hmacSecret],
      args: ["--auth-scope", "all"]
    )
    defer {
      relayProc.terminate()
      relayProc.waitUntilExit()
    }

    let host = try TendrilEndpoint(stateDir: nil, hostId: "swift-hmac-host")
    let cli = try TendrilEndpoint(stateDir: nil, hostId: "swift-hmac-cli")
    defer {
      host.close()
      cli.close()
    }

    #expect(throws: Error.self) {
      _ = try host.serveRelay(relayUrl: v1Url, expectedHost: "127.0.0.1")
    }
    try host.configureTransportsJSON("{\"relay_auth_secret\":\"wrong-secret\"}")
    #expect(throws: Error.self) {
      _ = try host.serveRelay(relayUrl: v1Url, expectedHost: "127.0.0.1")
    }

    let okCfg = "{\"relay_auth_secret\":\"\(hmacSecret)\"}"
    try host.configureTransportsJSON(okCfg)
    let v1Ep = try host.serveRelay(relayUrl: v1Url, expectedHost: "127.0.0.1")
    let code = try host.issueCode(kind: "remote")

    #expect(throws: Error.self) {
      _ = try cli.pairV2Initiate(endpoint: v1Ep, relayHost: "127.0.0.1", code: code, deviceName: "s")
    }
    try cli.configureTransportsJSON(okCfg)

    let accBox = SendableBox<String?>(nil)
    let accSem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      accBox.set(try? host.pairV2Accept(timeoutMs: 5000))
      accSem.signal()
    }
    let initJson = try cli.pairV2Initiate(
      endpoint: v1Ep, relayHost: "127.0.0.1", code: code, deviceName: "swift-hmac-dev", deviceKind: "swift"
    )
    #expect(accSem.wait(timeout: .now() + 5.0) == .success)
    let accJson = try #require(accBox.get())
    let initObj = try JSONSerialization.jsonObject(with: Data(initJson.utf8)) as! [String: Any]
    let accObj = try JSONSerialization.jsonObject(with: Data(accJson.utf8)) as! [String: Any]
    let sas = try #require(initObj["sas"] as? String)
    let cliDevId = try #require(accObj["device_id"] as? String)
    #expect(accObj["sas"] as? String == sas)

    try host.confirmPeer(peerId: cliDevId, sas: sas)
    try cli.confirmPeer(peerId: "swift-hmac-host", sas: sas)
    let grantJson = try host.mintGrant(peerId: cliDevId, capsJson: "[\"fs.read\"]", ttlSecs: 300)

    let v2Ep = try host.serveRelayV2(relayUrl: v2Url, expectedHost: "127.0.0.1")
    try cli.configureTransportsJSON("{\"relay_auth_secret\":\"wrong-secret\"}")
    #expect(throws: Error.self) {
      _ = try cli.connectV2(endpoint: v2Ep, relayHost: "127.0.0.1", targetHostId: "swift-hmac-host", grantJson: grantJson)
    }
    try cli.configureTransportsJSON(okCfg)

    let hostSessBox = SendableBox<TendrilSession?>(nil)
    let sessSem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      hostSessBox.set(try? host.acceptV2(timeoutMs: 5000))
      sessSem.signal()
    }
    let cliSess = try cli.connectV2(
      endpoint: v2Ep, relayHost: "127.0.0.1", targetHostId: "swift-hmac-host", grantJson: grantJson
    )
    defer { cliSess.free() }
    #expect(sessSem.wait(timeout: .now() + 5.0) == .success)
    let hostSess = try #require(hostSessBox.get())
    defer { hostSess.free() }

    try cliSess.sendData(Data("swift-hmac-v2".utf8))
    let evJson = try hostSess.pollEvent(timeoutMs: 3000)
    let evObj = try JSONSerialization.jsonObject(with: Data(evJson.utf8)) as! [String: Any]
    #expect(evObj["event"] as? String == "data")
    try cliSess.close(code: 1000, reason: "done")

    // Ticket-gated relay (/v1/relay and /v2/relay)
    let issuer = try TendrilEndpoint(stateDir: nil, hostId: "swift-ticket-issuer")
    defer { issuer.close() }
    let issuerInfo = try JSONSerialization.jsonObject(with: Data(issuer.infoJson().utf8)) as! [String: Any]
    let issuerPub = try #require(issuerInfo["relay_pub"] as? String)
    let regTicket = try issuer.mintRelayTicket(relayHost: "127.0.0.1", role: "register", targetPubOrWildcard: "*", ttlSecs: 300)
    let dialTicket = try issuer.mintRelayTicket(relayHost: "127.0.0.1", role: "dial", targetPubOrWildcard: "*", ttlSecs: 300)

    let (tRelayProc, tv1Url, tv2Url) = try startRelay(args: ["--issuer-pub", issuerPub, "--auth-scope", "all"])
    defer {
      tRelayProc.terminate()
      tRelayProc.waitUntilExit()
    }

    let tHost = try TendrilEndpoint(stateDir: nil, hostId: "swift-ticket-host")
    let tCli = try TendrilEndpoint(stateDir: nil, hostId: "swift-ticket-cli")
    defer {
      tHost.close()
      tCli.close()
    }

    try tHost.configureTransportsJSON("{\"relay_ticket\":\(dialTicket)}")
    #expect(throws: Error.self) {
      _ = try tHost.serveRelay(relayUrl: tv1Url, expectedHost: "127.0.0.1")
    }
    try tHost.configureTransportsJSON("{\"relay_ticket\":\(regTicket)}")
    let tv1Ep = try tHost.serveRelay(relayUrl: tv1Url, expectedHost: "127.0.0.1")
    let tCode = try tHost.issueCode(kind: "remote")

    try tCli.configureTransportsJSON("{\"relay_ticket\":\(regTicket)}")
    #expect(throws: Error.self) {
      _ = try tCli.pairV2Initiate(endpoint: tv1Ep, relayHost: "127.0.0.1", code: tCode, deviceName: "tc")
    }
    try tCli.configureTransportsJSON("{\"relay_ticket\":\(dialTicket)}")

    let tAccBox = SendableBox<String?>(nil)
    let tAccSem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      tAccBox.set(try? tHost.pairV2Accept(timeoutMs: 5000))
      tAccSem.signal()
    }
    let tInitJson = try tCli.pairV2Initiate(
      endpoint: tv1Ep, relayHost: "127.0.0.1", code: tCode, deviceName: "swift-t-dev", deviceKind: "swift"
    )
    #expect(tAccSem.wait(timeout: .now() + 5.0) == .success)
    let tAccJson = try #require(tAccBox.get())
    let tInitObj = try JSONSerialization.jsonObject(with: Data(tInitJson.utf8)) as! [String: Any]
    let tAccObj = try JSONSerialization.jsonObject(with: Data(tAccJson.utf8)) as! [String: Any]
    let tSas = try #require(tInitObj["sas"] as? String)
    let tCliDevId = try #require(tAccObj["device_id"] as? String)
    #expect(tAccObj["sas"] as? String == tSas)

    try tHost.confirmPeer(peerId: tCliDevId, sas: tSas)
    try tCli.confirmPeer(peerId: "swift-ticket-host", sas: tSas)
    let tGrant = try tHost.mintGrant(peerId: tCliDevId, capsJson: "[\"fs.read\"]", ttlSecs: 300)

    let tv2Ep = try tHost.serveRelayV2(relayUrl: tv2Url, expectedHost: "127.0.0.1")
    let tHostSessBox = SendableBox<TendrilSession?>(nil)
    let tSessSem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      tHostSessBox.set(try? tHost.acceptV2(timeoutMs: 5000))
      tSessSem.signal()
    }
    let tCliSess = try tCli.connectV2(
      endpoint: tv2Ep, relayHost: "127.0.0.1", targetHostId: "swift-ticket-host", grantJson: tGrant
    )
    defer { tCliSess.free() }
    #expect(tSessSem.wait(timeout: .now() + 5.0) == .success)
    let tHostSess = try #require(tHostSessBox.get())
    defer { tHostSess.free() }

    try tCliSess.sendData(Data("swift-ticket-v2".utf8))
    let tevJson = try tHostSess.pollEvent(timeoutMs: 3000)
    let tevObj = try JSONSerialization.jsonObject(with: Data(tevJson.utf8)) as! [String: Any]
    #expect(tevObj["event"] as? String == "data")
    try tCliSess.close(code: 1000, reason: "done")
  }

  @Test
  func wireV2ConformancePeerInterop() throws {
    let peerBin = repoRoot().appendingPathComponent("target/debug/tendril-conformance-peer")
    let peer = Process()
    peer.executableURL = peerBin
    let stdinPipe = Pipe()
    let stdoutPipe = Pipe()
    peer.standardInput = stdinPipe
    peer.standardOutput = stdoutPipe
    try peer.run()
    defer {
      peer.terminate()
      peer.waitUntilExit()
    }

    let writer = stdinPipe.fileHandleForWriting
    let reader = stdoutPipe.fileHandleForReading
    let bufBox = SendableBox<Data>(Data())

    func send(_ obj: [String: Any]) throws {
      let data = try JSONSerialization.data(withJSONObject: obj)
      writer.write(data)
      writer.write(Data("\n".utf8))
    }

    func recv() throws -> [String: Any] {
      while true {
        var cur = bufBox.get()
        if let nl = cur.firstIndex(of: 0x0A) {
          let line = cur.subdata(in: 0..<nl)
          cur.removeSubrange(0...nl)
          bufBox.set(cur)
          return try JSONSerialization.jsonObject(with: line) as! [String: Any]
        }
        let chunk = reader.availableData
        if chunk.isEmpty {
          throw TendrilError.ffi(code: -7, message: "conformance_peer EOF")
        }
        cur.append(chunk)
        bufBox.set(cur)
      }
    }

    func call(_ obj: [String: Any]) throws -> [String: Any] {
      try send(obj)
      let resp = try recv()
      #expect(resp["ok"] as? Bool == true)
      return resp
    }

    let cli = try TendrilEndpoint(stateDir: nil, hostId: "swift-v2-cli")
    defer { cli.close() }

    _ = try call(["op": "init", "host_id": "rust-swift-v2"])
    let srv = try call(["op": "serve_direct"])
    let ep = try #require(srv["endpoint"] as? String)
    let code = try #require(try call(["op": "issue_code", "kind": "lan"])["code"] as? String)

    try send(["op": "pair_v2_accept", "timeout_ms": 5000])
    let initJson = try cli.pairV2Initiate(endpoint: ep, code: code, deviceName: "swift-v2-dev", deviceKind: "swift")
    let initObj = try JSONSerialization.jsonObject(with: Data(initJson.utf8)) as! [String: Any]
    let peerPair = try recv()
    #expect(peerPair["ok"] as? Bool == true)
    let sas = try #require(initObj["sas"] as? String)
    #expect(peerPair["sas"] as? String == sas)
    let cliDevId = try #require(peerPair["device_id"] as? String)

    _ = try call(["op": "confirm", "peer_id": cliDevId, "sas": sas])
    let mintResp = try call(["op": "mint", "peer_id": cliDevId, "caps": ["fs.read"]])
    let grantData = try JSONSerialization.data(withJSONObject: mintResp["grant"]!)
    let grantJson = String(data: grantData, encoding: .utf8)!
    try cli.confirmPeer(peerId: "rust-swift-v2", sas: sas)

    try send(["op": "accept_v2", "timeout_ms": 5000])
    let sess = try cli.connectV2(endpoint: ep, targetHostId: "rust-swift-v2", grantJson: grantJson)
    defer { sess.free() }
    #expect(try recv()["ok"] as? Bool == true)
    #expect(try sess.peerId() == "rust-swift-v2")

    try sess.sendData(Data("swift-v2-hello".utf8))
    let ev = try call(["op": "recv", "timeout_ms": 2000])
    #expect(ev["event"] as? String == "data")
    #expect(ev["data_utf8"] as? String == "swift-v2-hello")

    try sess.rekey()
    _ = try call(["op": "send", "data_utf8": "rust-v2-reply"])
    var gotData: String?
    for _ in 0..<4 {
      let sevJson = try sess.pollEvent(timeoutMs: 2000)
      let sev = try JSONSerialization.jsonObject(with: Data(sevJson.utf8)) as! [String: Any]
      if sev["event"] as? String == "data", let b64 = sev["data_b64"] as? String {
        let padded = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let rem = padded.count % 4
        let full = rem == 0 ? padded : padded + String(repeating: "=", count: 4 - rem)
        if let raw = Data(base64Encoded: full) {
          gotData = String(data: raw, encoding: .utf8)
          break
        }
      }
    }
    #expect(gotData == "rust-v2-reply")
    #expect(try sess.authorize("fs.read") == true)
    #expect(try sess.authorize("shell.exec") == false)
    try sess.close(code: 1000, reason: "done")
    _ = try call(["op": "shutdown"])
  }
  #endif

  #if canImport(CryptoKit) && canImport(Security)
  @Test
  func keychainStoreCustomProviderRoundTripAndVersionGuard() throws {
    let key = SymmetricKey(size: .bits256)
    let store = TendrilKeychainStore(
      service: "dev.tendril.state.test",
      account: "custom-provider-\(UUID().uuidString)"
    ) {
      key
    }
    let payload = Data("sec22-keychain-roundtrip-state".utf8)
    let aad = Data("sec22-aad".utf8)

    let sealedWithAad = try store.sealState(payload, authenticating: aad)
    #expect(try store.openState(sealedWithAad, authenticating: aad) == payload)

    let sealedEmptyAad = try store.sealState(payload)
    #expect(try store.openState(sealedEmptyAad) == payload)
    #expect(throws: Error.self) {
      _ = try store.openState(sealedWithAad)
    }

    var wrongVersion = sealedWithAad
    wrongVersion[0] = 0x02
    #expect(throws: Error.self) {
      _ = try store.openState(wrongVersion, authenticating: aad)
    }
    #expect(throws: Error.self) {
      _ = try store.openState(Data([0x01]), authenticating: aad)
    }
  }

  #if os(macOS)
  @Test
  func keychainStoreRealKeychainRoundTrip() throws {
    let service = "dev.tendril.state.test"
    let account = "real-kc-\(UUID().uuidString)"
    let store = TendrilKeychainStore(service: service, account: account)
    defer {
      for (suffix, isSepOrV2) in [
        ("", false),
        (TendrilKeychainStore.sepP256AccountSuffix, true),
        (TendrilKeychainStore.v2CommittedAccountSuffix, true),
        (".sep-mldsa65", true),
      ] {
        SecItemDelete(
          store.keychainQueryBase(accountSuffix: suffix, isSepOrV2: isSepOrV2) as CFDictionary
        )
      }
    }
    do {
      let key1 = try store.loadOrCreateMasterKey()
      let key2 = try store.loadOrCreateMasterKey()
      #expect(key1.withUnsafeBytes { Data($0) } == key2.withUnsafeBytes { Data($0) })
      let payload = Data("sec22-real-keychain-state".utf8)
      let sealed = try store.sealState(payload)
      #expect(try store.openState(sealed) == payload)
    } catch TendrilKeychainError.osStatus(let status)
      where status == errSecWrPerm || status == errSecInteractionNotAllowed || status == -34018
    {
      print("[TendrilTests] NOTICE: live Keychain unavailable in headless CLI (OSStatus \(status))")
    }
  }
  #endif
  #endif
}

// MARK: Pairing URIs and routes

#if os(macOS) || os(Linux)
@Suite
struct TendrilRouteTests {
  private func obj(_ json: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
  }

  private func routes(_ client: TendrilEndpoint, _ host: String, source: String) throws -> [String] {
    let view = try obj(client.peerRoutes(peerId: host))
    return (view["routes"] as! [[String: Any]])
      .filter { $0["source"] as? String == source }
      .map { $0["hint"] as! String }
  }

  private func portOf(_ endpoint: String) -> String {
    String(endpoint.split(separator: ":").last!)
  }

  /// Pairs `client` with `host` from `uri`, confirms on the host and returns the client result
  /// and the host's device-side result.
  private func pair(
    host: TendrilEndpoint,
    client: TendrilEndpoint,
    uri: String,
    wire: Int = 1,
    saveRoute: Bool? = nil,
    routePolicy: String? = nil,
    endpoint: String? = nil
  ) throws -> (client: [String: Any], host: [String: Any]) {
    let hostBox = SendableBox<String>("")
    let sem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      hostBox.set(
        (try? (wire == 2 ? host.pairV2Accept(timeoutMs: 15_000) : host.pairAccept(timeoutMs: 15_000))) ?? ""
      )
      sem.signal()
    }
    let res =
      wire == 2
      ? try client.pairV2Uri(
        uri, name: "swift-phone", routePolicy: routePolicy, saveRoute: saveRoute, endpoint: endpoint)
      : try client.pairUri(
        uri, name: "swift-phone", routePolicy: routePolicy, saveRoute: saveRoute, endpoint: endpoint)
    #expect(sem.wait(timeout: .now() + 15.0) == .success)
    let hostRes = try obj(hostBox.get())
    let clientRes = try obj(res)
    #expect(clientRes["sas"] as? String == hostRes["sas"] as? String)
    try host.confirmPeer(peerId: hostRes["device_id"] as! String, sas: hostRes["sas"] as? String)
    return (clientRes, hostRes)
  }

  private func accepting<T>(
    host: TendrilEndpoint, wire: Int = 1, _ connect: () throws -> T
  ) throws -> (T, TendrilSession) {
    let box = SendableBox<TendrilSession?>(nil)
    let sem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      box.set(try? (wire == 2 ? host.acceptV2(timeoutMs: 8000) : host.acceptSession(timeoutMs: 8000)))
      sem.signal()
    }
    let client: T
    do {
      client = try connect()
    } catch {
      _ = sem.wait(timeout: .now() + 9.0)
      box.get()?.free()
      throw error
    }
    #expect(sem.wait(timeout: .now() + 9.0) == .success)
    return (client, try #require(box.get()))
  }

  private func roundTrip(_ client: TendrilSession, _ host: TendrilSession, _ text: String) throws {
    try client.sendData(Data(text.utf8))
    let ev = try obj(host.pollEvent(timeoutMs: 3000))
    #expect(ev["event"] as? String == "data")
  }

  private struct Paired {
    let host: TendrilEndpoint
    let client: TendrilEndpoint
    let hostId: String
    let peerId: String
    let listen: String
    let grant: String
    let pair: [String: Any]
    let issued: [String: Any]
  }

  private func paired(wire: Int = 1) throws -> Paired {
    let host = try TendrilEndpoint(hostId: "swift-routes-host")
    let client = try TendrilEndpoint(hostId: "swift-routes-client")
    let listen = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let issued = try obj(host.issuePairingUri())
    let res = try pair(host: host, client: client, uri: issued["uri"] as! String, wire: wire)
    let peerId = res.host["device_id"] as! String
    let grant = try host.mintGrant(
      peerId: peerId, capsJson: "[\"fs.read\"]", ttlSecs: 3600)
    return Paired(
      host: host, client: client, hostId: "swift-routes-host", peerId: peerId, listen: listen,
      grant: grant, pair: res.client, issued: issued)
  }

  @Test
  func signedPairingPersistsAllRoutesAndConnectsWithoutEndpoint() throws {
    let p = try paired()
    defer {
      p.host.close()
      p.client.close()
    }
    let uri = p.issued["uri"] as! String
    #expect(uri.contains("&rq=") && uri.contains("&rs="))
    #expect(p.issued["code_kind"] as? String == "lan")
    #expect(p.issued["uri_len"] as? Int == uri.utf8.count)
    #expect(URL(string: uri)?.absoluteString == uri)
    #expect(p.pair["route_check"] as? String == "verified")
    #expect(p.pair["committed"] as? Bool == true)
    #expect(p.pair["provider"] as? String == "direct")
    #expect(try routes(p.client, p.hostId, source: "signed") == ["direct:\(p.listen)"])
    let view = try obj(p.client.peerRoutes(peerId: p.hostId))
    #expect((view["route_meta"] as! [String: Any])["origin"] as? String == "uri")

    let (cli, srv) = try accepting(host: p.host) {
      try p.client.connect(targetHostId: p.hostId, grantJson: p.grant)
    }
    defer {
      cli.free()
      srv.free()
    }
    try roundTrip(cli, srv, "over stored route")
  }

  @Test
  func wireV2UriPairingAndEndpointFreeConnect() throws {
    let p = try paired(wire: 2)
    defer {
      p.host.close()
      p.client.close()
    }
    #expect(p.pair["route_check"] as? String == "verified")
    let (cli, srv) = try accepting(host: p.host, wire: 2) {
      try p.client.connectV2(targetHostId: p.hostId, grantJson: p.grant)
    }
    defer {
      cli.free()
      srv.free()
    }
    #expect(try cli.peerId() == p.hostId)
    #expect(try srv.peerId() == p.peerId)
    try roundTrip(cli, srv, "v2 stored")
  }

  @Test
  func issueAndPairOptions() throws {
    let host = try TendrilEndpoint(hostId: "swift-opt-host")
    let client = try TendrilEndpoint(hostId: "swift-opt-client")
    let client2 = try TendrilEndpoint(hostId: "swift-opt-client2")
    defer {
      host.close()
      client.close()
      client2.close()
    }
    let listen = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let remote = try obj(host.issuePairingUri(kind: "remote", hostName: "Studio"))
    #expect(remote["code_kind"] as? String == "remote")
    #expect((remote["uri"] as! String).contains("Studio"))
    #expect(throws: Error.self) { _ = try host.issuePairingUri(kind: "bluetooth") }

    let unsigned = try obj(host.issuePairingUri(signRoutes: false))
    let uri = unsigned["uri"] as! String
    #expect(!uri.contains("&rs="))
    let res = try pair(host: host, client: client, uri: uri).client
    #expect(res["route_check"] as? String == "unsigned")
    #expect((res["routes_persisted"] as! [Any]).isEmpty)

    let again = try obj(host.issuePairingUri(signRoutes: false))["uri"] as! String
    let saved = try pair(host: host, client: client2, uri: again, saveRoute: true).client
    let persisted = saved["routes_persisted"] as! [[String: Any]]
    #expect(persisted.map { $0["hint"] as? String } == ["direct:\(listen)"])
    #expect(persisted.map { $0["source"] as? String } == ["committed"])

    #expect(throws: Error.self) { _ = try client.pairUri("tendril://nope") }
    #expect(throws: Error.self) { _ = try client.pairUri(uri, routePolicy: "sometimes") }
    #expect(throws: Error.self) { _ = try client.pairUri("a\u{0}b") }
  }

  @Test
  func peerRouteSetterReplacesOperatorRoutesAtomically() throws {
    let p = try paired()
    defer {
      p.host.close()
      p.client.close()
    }
    try p.client.setPeerRoutes(peerId: p.hostId, routes: ["direct:127.0.0.1:41001"])
    try p.client.setPeerRoutes(peerId: p.hostId, routes: ["direct:127.0.0.1:41002", "direct:127.0.0.1:41003"])
    #expect(
      try routes(p.client, p.hostId, source: "operator")
        == ["direct:127.0.0.1:41002", "direct:127.0.0.1:41003"])
    #expect(try routes(p.client, p.hostId, source: "signed") == ["direct:\(p.listen)"])

    #expect(throws: Error.self) {
      try p.client.setPeerRoutes(peerId: p.hostId, routes: ["direct:127.0.0.1:41004", "bogus://"])
    }
    #expect(
      try routes(p.client, p.hostId, source: "operator")
        == ["direct:127.0.0.1:41002", "direct:127.0.0.1:41003"])
    #expect(throws: Error.self) { try p.client.setPeerRoutes(peerId: p.hostId, routes: ["a\u{0}b"]) }
    expectFfiCode(TENDRIL_ERR_NOT_FOUND.rawValue) {
      try p.client.setPeerRoutes(peerId: "dev_unknown", routes: ["direct:127.0.0.1:41005"])
    }
    expectFfiCode(TENDRIL_ERR_NOT_FOUND.rawValue) { _ = try p.client.peerRoutes(peerId: "dev_unknown") }

    try p.client.clearPeerRoutes(peerId: p.hostId)
    #expect(try routes(p.client, p.hostId, source: "operator").isEmpty)
    #expect(try routes(p.client, p.hostId, source: "signed").count == 1)
    try p.client.clearPeerRoutes(peerId: p.hostId, source: "all")
    #expect((try obj(p.client.peerRoutes(peerId: p.hostId))["routes"] as! [Any]).isEmpty)
  }

  /// Records an issue unless `body` throws the FFI error with `code`.
  private func expectFfiCode(_ code: Int32, _ body: () throws -> Void) {
    do {
      try body()
      Issue.record("expected FFI error \(code)")
    } catch TendrilError.ffi(let got, let message) {
      #expect(got == code, "\(message)")
    } catch {
      Issue.record("expected FFI error \(code), got \(error)")
    }
  }

  @Test
  func pairResultReportsRoutesReason() throws {
    let p = try paired()
    defer {
      p.host.close()
      p.client.close()
    }
    // A verified, persisted pairing has nothing to explain.
    #expect(p.pair["route_check"] as? String == "verified")
    #expect(p.pair["routes_reason"] is NSNull)

    // An unsigned URI writes no routes unless asked, and says why.
    let unsigned = try obj(p.host.issuePairingUri(signRoutes: false))["uri"] as! String
    let second = try TendrilEndpoint(hostId: "swift-reason-client")
    defer { second.close() }
    let res = try pair(host: p.host, client: second, uri: unsigned).client
    #expect(res["route_check"] as? String == "unsigned")
    #expect((res["routes_persisted"] as! [Any]).isEmpty)
    #expect(res["routes_reason"] as? String == "unsigned_uri")
  }

  @Test
  func connectWithOptionsForwardsRelayHost() throws {
    let p = try paired()
    defer {
      p.host.close()
      p.client.close()
    }
    // For an `iroh://` endpoint `relayHost` selects the Iroh relay mode. The core's relay-mode
    // parser rejects an unknown value, so this message proves the field reached the dialer.
    do {
      _ = try p.client.connectWithOptions(
        targetHostId: p.hostId, grantJson: p.grant, endpoint: "iroh://peer",
        relayHost: "not-a-relay-mode")
      Issue.record("expected the relay mode to be rejected")
    } catch TendrilError.ffi(_, let message) {
      #expect(message.contains("invalid p2p relay mode"), "\(message)")
    }
    #expect(throws: TendrilError.invalidArgument("relay_host contains interior NUL byte")) {
      _ = try p.client.connectWithOptions(
        targetHostId: p.hostId, grantJson: p.grant, relayHost: "a\u{0}b")
    }
  }

  @Test
  func connectWithOptionsRelayHostDialsALocalP2pListener() throws {
    let host = try TendrilEndpoint(hostId: "swift-p2p-host")
    let client = try TendrilEndpoint(hostId: "swift-p2p-client")
    defer {
      host.close()
      client.close()
    }
    let addr = try host.serveP2p(relayMode: "disabled")
    // A LAN code is refused on a remote (iroh) path, so the code is a remote one.
    let code = try host.issueCode(kind: "remote")
    let hostBox = SendableBox<String>("")
    let sem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      hostBox.set((try? host.pairAccept(timeoutMs: 15_000)) ?? "")
      sem.signal()
    }
    let clientRes = try obj(
      client.pairInitiate(
        endpoint: addr, relayHost: "disabled", code: code, deviceName: "swift-p2p", deviceKind: "swift"))
    #expect(sem.wait(timeout: .now() + 15.0) == .success)
    let hostRes = try obj(hostBox.get())
    let peerId = hostRes["device_id"] as! String
    #expect(clientRes["sas"] as? String == hostRes["sas"] as? String)
    try host.confirmPeer(peerId: peerId, sas: hostRes["sas"] as? String)
    try client.confirmPeer(peerId: "swift-p2p-host", sas: clientRes["sas"] as? String)
    let grant = try host.mintGrant(peerId: peerId, capsJson: "[\"fs.read\"]", ttlSecs: 3600)

    // `relayHost: "disabled"` selects the no-relay mode, so the local listener is reachable.
    let (cli, srv) = try accepting(host: host) {
      try client.connectWithOptions(
        targetHostId: "swift-p2p-host", grantJson: grant, endpoint: addr, relayHost: "disabled")
    }
    defer {
      cli.free()
      srv.free()
    }
    try roundTrip(cli, srv, "over p2p with relayHost")
  }

  @Test
  func applyRouteUriOffline() throws {
    let p = try paired()
    defer {
      p.host.close()
      p.client.close()
    }
    let first = (try obj(p.client.peerRoutes(peerId: p.hostId))["route_meta"] as! [String: Any])["seq"] as! Int
    let stale = try obj(p.host.issuePairingUri())["uri"] as! String
    let second = try p.host.serveDirect(listenAddr: "127.0.0.1:0")
    let fresh = try obj(p.host.issuePairingUri())
    #expect(fresh["route_seq"] as? Int == first + 1)

    var res = try obj(p.client.applyRouteUri(fresh["uri"] as! String))
    #expect(res["applied"] as? Bool == true)
    #expect(res["route_seq"] as? Int == first + 1)
    #expect(
      Set(try routes(p.client, p.hostId, source: "signed")) == ["direct:\(p.listen)", "direct:\(second)"])

    res = try obj(p.client.applyRouteUri(stale))
    #expect(res["applied"] as? Bool == false)
    #expect(res["reason"] as? String == "stale_route_seq")
    res = try obj(p.client.applyRouteUri(stale, replaceRoutes: true))
    #expect(res["applied"] as? Bool == true)
    #expect(try routes(p.client, p.hostId, source: "signed") == ["direct:\(p.listen)"])
    res = try obj(p.client.applyRouteUri(fresh["uri"] as! String, routePolicy: "committed_only"))
    #expect(res["applied"] as? Bool == false)
    #expect(res["reason"] as? String == "route_policy")
    #expect(throws: Error.self) { _ = try p.client.applyRouteUri("not a uri") }
  }

  @Test
  func connectWithOptionsUsesRecoveryUri() throws {
    let p = try paired()
    defer {
      p.host.close()
      p.client.close()
    }
    try p.client.clearPeerRoutes(peerId: p.hostId, source: "all")
    #expect(throws: Error.self) { _ = try p.client.connect(targetHostId: p.hostId, grantJson: p.grant) }

    let recovery = try obj(p.host.issuePairingUri())["uri"] as! String
    let (cli, srv) = try accepting(host: p.host) {
      try p.client.connectWithOptions(
        targetHostId: p.hostId, grantJson: p.grant, recoveryUri: recovery)
    }
    try roundTrip(cli, srv, "recovered")
    cli.free()
    srv.free()

    let stranger = try TendrilEndpoint(hostId: "swift-stranger")
    defer { stranger.close() }
    _ = try stranger.serveDirect(listenAddr: "127.0.0.1:0")
    let foreign = try obj(stranger.issuePairingUri())["uri"] as! String
    #expect(throws: Error.self) {
      _ = try p.client.connectWithOptions(
        targetHostId: p.hostId, grantJson: p.grant, recoveryUri: foreign)
    }
    #expect(throws: Error.self) { _ = try p.client.connectWithOptions(targetHostId: p.hostId, wire: 3) }
    #expect(throws: Error.self) {
      _ = try p.client.connectWithOptions(targetHostId: p.hostId, grantJson: "{not json")
    }
  }

  private func snapshot(_ networks: [(id: String, iface: String, index: Int, transports: [String], addrs: [String])])
    throws -> String
  {
    let list = networks.map { n -> [String: Any] in
      ["id": n.id, "iface": n.iface, "if_index": n.index, "transports": n.transports, "addrs": n.addrs]
    }
    let data = try JSONSerialization.data(withJSONObject: ["networks": list])
    return String(decoding: data, as: UTF8.self)
  }

  /// Drives `cli` until `client` records an applied route set `seq` from `hostId`.
  private func waitRouteSet(_ client: TendrilEndpoint, _ cli: TendrilSession, _ hostId: String, seq: Int) throws {
    let deadline = Date().addingTimeInterval(15)
    while Date() < deadline {
      do {
        _ = try cli.pollEvent(timeoutMs: 250)
        Issue.record("route sets never reach the event stream")
        return
      } catch TendrilError.wouldBlock {
      }
      let view = try obj(client.peerRoutes(peerId: hostId))
      if let last = view["last_route_set"] as? [String: Any],
        last["outcome"] as? String == "applied", last["seq"] as? Int == seq
      {
        #expect((view["route_meta"] as! [String: Any])["origin"] as? String == "session")
        return
      }
    }
    Issue.record("route set \(seq) not applied")
  }

  @Test
  func refreshRoutesDeliversRouteSetAndReconnects() throws {
    let host = try TendrilEndpoint(hostId: "swift-refresh-host")
    let client = try TendrilEndpoint(hostId: "swift-refresh-client")
    defer {
      host.close()
      client.close()
    }
    let loopback = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let any = try host.serveDirect(listenAddr: "0.0.0.0:0")
    let lanPort = portOf(any)
    func net(_ addr: String) throws -> String {
      try snapshot([(id: "net-1", iface: "en0", index: 3, transports: ["wifi"], addrs: [addr])])
    }

    let seq0 = try obj(host.refreshRoutes(snapshotJson: net("10.255.77.20")))["route_seq"] as! Int
    let issued = try obj(host.issuePairingUri())
    #expect(issued["route_seq"] as? Int == seq0)
    let uri = issued["uri"] as! String
    #expect(uri.contains("10.255.77.20"))
    let res = try pair(host: host, client: client, uri: uri)
    let grant = try host.mintGrant(
      peerId: res.host["device_id"] as! String, capsJson: "[\"fs.read\"]", ttlSecs: 3600)
    let hostId = "swift-refresh-host"
    #expect(
      Set(try routes(client, hostId, source: "signed"))
        == ["direct:\(loopback)", "direct:10.255.77.20:\(lanPort)"])

    var (cli, srv) = try accepting(host: host) {
      try client.connect(targetHostId: hostId, grantJson: grant)
    }
    try waitRouteSet(client, cli, hostId, seq: seq0)
    cli.free()
    srv.free()

    (cli, srv) = try accepting(host: host) {
      try client.connect(targetHostId: hostId, grantJson: grant)
    }
    defer {
      cli.free()
      srv.free()
    }
    let same = try obj(host.refreshRoutes(snapshotJson: net("10.255.77.20")))
    #expect(same["changed"] as? Bool == false)
    #expect(same["route_seq"] as? Int == seq0)
    let moved = try obj(host.refreshRoutes(snapshotJson: net("10.255.77.30")))
    #expect(moved["changed"] as? Bool == true)
    #expect(moved["route_seq"] as? Int == seq0 + 1)
    try waitRouteSet(client, cli, hostId, seq: seq0 + 1)
    let signed = try routes(client, hostId, source: "signed")
    #expect(signed.contains("direct:10.255.77.30:\(lanPort)"))
    #expect(!signed.contains("direct:10.255.77.20:\(lanPort)"))
    #expect(signed.contains("direct:\(loopback)"))
    try srv.sendData(Data("still open".utf8))

    // The next endpoint-free connect uses the updated routes without any prompt.
    let (cli2, srv2) = try accepting(host: host) {
      try client.connect(targetHostId: hostId, grantJson: grant)
    }
    defer {
      cli2.free()
      srv2.free()
    }
    try roundTrip(cli2, srv2, "after address change")

    #expect(throws: Error.self) { _ = try host.refreshRoutes(snapshotJson: "{\"networks\": 1}") }
    _ = try host.refreshRoutes()
  }

  #if canImport(Network)
  @Test
  func pathUpdateRefreshesRoutes() throws {
    let host = try TendrilEndpoint(hostId: "swift-monitor-host")
    defer { host.close() }
    _ = try host.serveDirect(listenAddr: "0.0.0.0:0")
    #expect(!host.isPathMonitoring)
    let queue = DispatchQueue(label: "tendril.swift.test-path")
    try host.startPathMonitoring(queue: queue)
    #expect(host.isPathMonitoring)
    // An NWPathMonitor update reaches refreshRoutes(): a snapshot-free refresh succeeds and the
    // endpoint then publishes a route set. The real monitor may also report its initial path.
    let before = host.pathRefreshCount
    host.firePathUpdate()
    #expect(host.pathRefreshCount >= before + 1)
    let issued = try obj(host.issuePairingUri())
    #expect((issued["route_seq"] as? Int ?? 0) >= 1)
    host.stopPathMonitoring()
    #expect(!host.isPathMonitoring)
    queue.sync {}
    let stopped = host.pathRefreshCount
    host.firePathUpdate()
    #expect(host.pathRefreshCount == stopped)
    try host.startPathMonitoring()
    host.close()
    #expect(!host.isPathMonitoring)
  }

  @Test
  func pathMonitorNeverSurvivesCloseOrLosesToStop() throws {
    // Start after close throws and installs nothing.
    let closed = try TendrilEndpoint(hostId: "swift-monitor-closed")
    closed.close()
    #expect(throws: TendrilError.closed) { try closed.startPathMonitoring() }
    #expect(!closed.isPathMonitoring)

    // A monitor cancelled before it starts refuses to start.
    let cancelledMonitor = TendrilPathMonitor(queue: DispatchQueue(label: "tendril.swift.test-cancelled")) {}
    cancelledMonitor.cancel()
    #expect(!cancelledMonitor.start())
    let liveMonitor = TendrilPathMonitor(queue: DispatchQueue(label: "tendril.swift.test-live")) {}
    #expect(liveMonitor.start())
    liveMonitor.cancel()

    // Concurrent start, stop and close: no monitor outlives close.
    for round in 0..<20 {
      let host = try TendrilEndpoint(hostId: "swift-monitor-race-\(round)")
      let group = DispatchGroup()
      for i in 0..<6 {
        DispatchQueue.global().async(group: group) {
          switch i % 3 {
          case 0: try? host.startPathMonitoring()
          case 1: host.stopPathMonitoring()
          default: host.close()
          }
        }
      }
      group.wait()
      host.close()
      #expect(!host.isPathMonitoring, "round \(round)")
    }

    // Concurrent start and stop: a monitor left installed is a live one, never a cancelled one.
    let host = try TendrilEndpoint(hostId: "swift-monitor-live")
    defer { host.close() }
    for round in 0..<50 {
      let group = DispatchGroup()
      for i in 0..<4 {
        DispatchQueue.global().async(group: group) {
          if i % 2 == 0 { try? host.startPathMonitoring() } else { host.stopPathMonitoring() }
        }
      }
      group.wait()
      #expect(!host.pathMonitorIsCancelled, "round \(round)")
    }
  }

  #endif

  @Test
  func closeClearsCachedTransportConfig() throws {
    let host = try TendrilEndpoint(hostId: "swift-cache-close")
    try host.configureTransportsJSON("{\"route_policy\":\"committed_only\"}")
    #expect(host.cachedTransportKeyCount == 1)
    #expect(throws: Error.self) { try host.configureRoutes(routePolicy: "sometimes") }
    #expect(host.cachedTransportKeyCount == 1)
    host.close()
    #expect(host.cachedTransportKeyCount == 0)
  }

  @Test
  func multiNetworkSnapshotAdvertisesLanAndOverlayOnly() throws {
    let host = try TendrilEndpoint(hostId: "swift-multinet-host")
    defer { host.close() }
    let any = try host.serveDirect(listenAddr: "0.0.0.0:0")
    let port = portOf(any)
    let snap = try snapshot([
      (id: "wifi", iface: "en0", index: 4, transports: ["wifi"], addrs: ["192.168.50.7"]),
      (id: "vpn", iface: "utun3", index: 9, transports: ["vpn"], addrs: ["100.101.1.2"]),
      (id: "cell", iface: "pdp_ip0", index: 6, transports: ["cellular"], addrs: ["100.72.0.5"]),
    ])
    _ = try host.refreshRoutes(snapshotJson: snap)
    // A LAN code carries the LAN hint only, a remote code the LAN and overlay hints; the
    // cellular CGNAT address is in neither.
    func hints(_ kind: String) throws -> String {
      let uri = try obj(host.issuePairingUri(kind: kind))["uri"] as! String
      #expect(URL(string: uri)?.absoluteString == uri)
      return uri.removingPercentEncoding ?? uri
    }
    let lan = try hints("lan")
    let remote = try hints("remote")
    #expect(lan.contains("direct:192.168.50.7:\(port)"), "\(lan)")
    #expect(!lan.contains("100.101.1.2"), "\(lan)")
    #expect(remote.contains("overlay://100.101.1.2:\(port)"), "\(remote)")
    #expect(remote.contains("direct:192.168.50.7:\(port)"), "\(remote)")
    #expect(!lan.contains("100.72.0.5") && !remote.contains("100.72.0.5"))
  }

  @Test
  func configureRoutesKeys() throws {
    let ep = try TendrilEndpoint(hostId: "swift-cfg-routes")
    defer { ep.close() }
    try ep.configureRoutes(
      advertisedEndpoints: ["192.168.40.1:4100"],
      relayAuthOrigins: ["https://relay.example.com"],
      advertise: "explicit",
      routePolicy: "committed_only",
      signRoutes: true)
    #expect(throws: Error.self) { try ep.configureRoutes(advertise: "sometimes") }
    #expect(throws: Error.self) { try ep.configureRoutes(relayAuthOrigins: ["not an origin"]) }
    #expect(throws: Error.self) { try ep.configureRoutes(routePolicy: "a\u{0}b") }
    let uri = try obj(ep.issuePairingUri())["uri"] as! String
    #expect(uri.contains("192.168.40.1"))
  }

  @Test
  func configureP2pReachesTheListenerAndIsValidated() throws {
    let ep = try TendrilEndpoint(hostId: "swift-p2p-net")
    defer { ep.close() }
    try ep.configureRoutes(advertise: "explicit", routePolicy: "committed_only")
    try ep.configureP2p(portMapping: false, bindAddrs: ["127.0.0.1:0"])
    // The merge keeps the route keys sent before and adds the two P2P keys.
    #expect(ep.cachedTransportKeyCount == 4)

    let addr = try ep.serveP2p(relayMode: "disabled")
    let hints = addr.components(separatedBy: CharacterSet(charactersIn: "?&"))
      .filter { $0.hasPrefix("addr=") }
      .map { String($0.dropFirst("addr=".count)) }
    #expect(!hints.isEmpty, "\(addr)")
    for hint in hints {
      #expect(hint.hasPrefix("127.0.0.1:"), "\(addr)")
    }

    for bad in [["not-an-addr"], ["127.0.0.1:0", "127.0.0.2:0"]] {
      do {
        try ep.configureP2p(bindAddrs: bad)
        Issue.record("expected \(bad) to be rejected")
      } catch TendrilError.ffi(let code, let message) {
        #expect(code == TENDRIL_ERR_INVALID_ARG.rawValue)
        #expect(message.contains("p2p_bind_addrs"), "\(message)")
      }
    }
    #expect(ep.cachedTransportKeyCount == 4)
    #expect(throws: TendrilError.invalidArgument("p2p_bind_addrs contains interior NUL byte")) {
      try ep.configureP2p(bindAddrs: ["127.0.0.1:0\u{0}"])
    }
    try ep.configureP2p(portMapping: true, bindAddrs: [])
    #expect(ep.cachedTransportKeyCount == 4)
  }

  @Test
  func configureP2pKeepsUnsetKeysAndWholeConfigurationKeys() throws {
    let ep = try TendrilEndpoint(hostId: "swift-p2p-merge")
    defer { ep.close() }
    // A key sent through the whole-configuration call survives configureP2p.
    try ep.configureTransportsJSON("{\"p2p_relay_mode\":\"disabled\",\"p2p_pkarr\":false}")
    try ep.configureP2p(portMapping: false)
    #expect(ep.cachedTransportKeyCount == 3)
    // A nil argument keeps the earlier value of that key; setting the other changes only it.
    try ep.configureP2p(bindAddrs: ["127.0.0.1:0"])
    #expect(ep.cachedTransportKeyCount == 4)
    #expect(ep.cachedTransportValue("p2p_port_mapping") as? Bool == false)
    #expect(ep.cachedTransportValue("p2p_bind_addrs") as? [String] == ["127.0.0.1:0"])
    #expect(ep.cachedTransportValue("p2p_relay_mode") as? String == "disabled")
    try ep.configureP2p(portMapping: true)
    #expect(ep.cachedTransportValue("p2p_port_mapping") as? Bool == true)
    #expect(ep.cachedTransportValue("p2p_bind_addrs") as? [String] == ["127.0.0.1:0"])
    // The kept bind address is still the one the listener uses.
    let addr = try ep.serveP2p()
    let hints = addr.components(separatedBy: CharacterSet(charactersIn: "?&"))
      .filter { $0.hasPrefix("addr=") }
    #expect(!hints.isEmpty, "\(addr)")
    #expect(hints.allSatisfy { $0.hasPrefix("addr=127.0.0.1:") }, "\(addr)")
  }

  #if canImport(CryptoKit) && canImport(Security)
  @Test
  func sealedRouteSeqSurvivesRestart() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("tendril-swift-seq-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: dir) }
    let key = SymmetricKey(size: .bits256)
    let kc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "seq") { key }

    func seq(_ ep: TendrilEndpoint, _ hint: String) throws -> Int {
      try ep.configureRoutes(advertisedEndpoints: [hint], advertise: "explicit")
      return try obj(ep.issuePairingUri())["route_seq"] as! Int
    }
    var host = try TendrilEndpoint(stateDir: dir.path, keychainStore: kc)
    let a = try seq(host, "192.168.40.1:4100")
    let b = try seq(host, "192.168.40.1:4101")
    #expect(b == a + 1)
    host.close()

    host = try TendrilEndpoint(stateDir: dir.path, keychainStore: kc)
    defer { host.close() }
    #expect(try seq(host, "192.168.40.1:4101") == b)
    #expect(try seq(host, "192.168.40.1:4102") == b + 1)
  }
  #endif

  #if os(macOS) && canImport(CoreImage) && canImport(Vision)
  @Test
  func scannerPassthroughDecodesBuilderOutputByteForByte() throws {
    let host = try TendrilEndpoint(hostId: "swift-scan-host")
    let client = try TendrilEndpoint(hostId: "swift-scan-client")
    defer {
      host.close()
      client.close()
    }
    _ = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let uri = try obj(host.issuePairingUri())["uri"] as! String

    let filter = try #require(CIFilter(name: "CIQRCodeGenerator"))
    filter.setValue(Data(uri.utf8), forKey: "inputMessage")
    filter.setValue("M", forKey: "inputCorrectionLevel")
    let qr = try #require(filter.outputImage).transformed(by: CGAffineTransform(scaleX: 8, y: 8))
    let page = qr.extent.insetBy(dx: -64, dy: -64)
    let white = CIImage(color: .white).cropped(to: page)
    let image = qr.composited(over: white)
    let cg = try #require(CIContext().createCGImage(image, from: page))

    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    try VNImageRequestHandler(cgImage: cg, options: [:]).perform([request])
    let decoded = try #require(request.results?.first?.payloadStringValue)
    #expect(Array(decoded.utf8) == Array(uri.utf8))

    let res = try pair(host: host, client: client, uri: decoded).client
    #expect(res["route_check"] as? String == "verified")
  }
  #endif

  @Test
  func lowPowerOptionsConfigurePowerIdleTimeoutAndExternalMonitor() throws {
    let encodedDefault = try encodeSealedEndpointOptionsJson(TendrilEndpointOptions())
    let defaultObj = try obj(encodedDefault)
    #expect(defaultObj["power_profile"] == nil)

    let encodedLow = try encodeSealedEndpointOptionsJson(TendrilEndpointOptions.lowPowerHost)
    let lowObj = try obj(encodedLow)
    #expect(lowObj["power_profile"] as? String == "low_power")

    let encodedExt = try encodeSealedEndpointOptionsJson(TendrilEndpointOptions.extensionClientOnly)
    let extObj = try obj(encodedExt)
    #expect(extObj["runtime_profile"] as? String == "extension")
    #expect(extObj["client_only"] as? Bool == true)
    #expect(extObj["power_profile"] as? String == "low_power")

    let p = try paired(wire: 2)
    defer {
      p.host.close()
      p.client.close()
    }
    try p.host.configurePower(powerProfile: .lowPower)
    try p.client.configurePower(powerProfile: .lowPower)
    #expect(p.client.cachedTransportValue("power_profile") as? String == "low_power")
    #expect(throws: Error.self) {
      try p.client.configurePower(wakeRetryMaxDelayMs: 2000)
    }
    #expect(throws: Error.self) {
      _ = try p.client.connectWithOptions(targetHostId: p.hostId, wire: 2, idleTimeoutMs: 0)
    }

    try p.host.setExternalPathMonitor(true)
    _ = try p.host.refreshRoutes()
    try p.host.setExternalPathMonitor(false)

    let (cli, srv) = try accepting(host: p.host, wire: 2) {
      try p.client.connectWithOptions(
        targetHostId: p.hostId, wire: 2, grantJson: p.grant, idleTimeoutMs: 5000
      )
    }
    try roundTrip(cli, srv, "swift-low-power")
    cli.free()
    srv.free()
  }
}
#endif

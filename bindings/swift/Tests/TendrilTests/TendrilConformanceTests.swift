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

    DispatchQueue.global().async {
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
    DispatchQueue.global().async {
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
    DispatchQueue.global().async {
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
    DispatchQueue.global().async {
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
    DispatchQueue.global().async {
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
      let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
      ]
      SecItemDelete(query as CFDictionary)
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

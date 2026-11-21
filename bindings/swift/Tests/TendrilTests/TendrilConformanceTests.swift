import Foundation
import XCTest
@testable import Tendril

final class TendrilConformanceTests: XCTestCase {
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

  func testConformanceVectors() throws {
    let fp = try loadJson("fingerprints.json")
    let rawPub = hexData(fp["raw_pubkey_hex"] as! String)
    let hh = hexData(fp["handshake_hash_hex"] as! String)
    XCTAssertEqual(try TendrilCrypto.deviceId(staticPub: rawPub), fp["raw_device_id"] as? String)
    XCTAssertEqual(
      try TendrilCrypto.fingerprintHost(staticPub: rawPub),
      fp["raw_host_fingerprint"] as? String
    )
    XCTAssertEqual(
      try TendrilCrypto.fingerprintDevice(staticPub: rawPub),
      fp["raw_device_fingerprint"] as? String
    )
    XCTAssertEqual(try TendrilCrypto.pairingSas(handshakeHash: hh), fp["pairing_sas"] as? String)

    let pm = try loadJson("pairing_mac.json")
    let pmHh = hexData(pm["handshake_hash_hex"] as! String)
    let r3 = pm["remote_3group"] as! [String: Any]
    XCTAssertEqual(
      try TendrilCrypto.computeCodeMac(code: r3["code"] as! String, handshakeHash: pmHh),
      hexData(r3["code_mac_hex"] as! String)
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
    XCTAssertEqual(finalSeq, 2)

    let forkEntry = (rot["fork_record"] as! [String: Any])["record"] as! [String: Any]
    let forkJson = String(
      data: try JSONSerialization.data(withJSONObject: [records[0], forkEntry]),
      encoding: .utf8
    )!
    XCTAssertThrowsError(
      try TendrilCrypto.verifyRotationChainJson(
        pinnedSigningB64: pSig,
        pinnedStaticB64: pStat,
        pinnedSeq: 0,
        chainJson: forkJson,
        curStaticB64: lastRec["new_static_pub"] as! String,
        curSigningB64: lastRec["new_signing_pub"] as! String
      )
    )

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
    XCTAssertTrue(
      try TendrilCrypto.verifyGrantJson(
        grantJson: validJson,
        issuerKeysJson: keysJson,
        expectedSubject: leafId,
        expectedRootIssuer: rootId,
        requestedCap: "fs.read:/photos/2026/a.jpg",
        nowUnix: 1795564800
      )
    )
    XCTAssertFalse(
      try TendrilCrypto.verifyGrantJson(
        grantJson: widenedJson,
        issuerKeysJson: keysJson,
        expectedSubject: leafId,
        expectedRootIssuer: rootId,
        requestedCap: "fs.read:/photos/2026/a.jpg",
        nowUnix: 1795564800
      )
    )
  }

  func testLocalEndpointLifecycle() throws {
    let host = try TendrilEndpoint(hostId: "swift-host")
    let client = try TendrilEndpoint(hostId: "swift-client")
    defer {
      host.close()
      client.close()
    }

    let addr = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let code = try host.issueCode(kind: "lan")

    let pairQueue = DispatchQueue(label: "tendril.swift.pair")
    let pairExp = expectation(description: "pair accept")
    var acceptJson = ""
    pairQueue.async {
      acceptJson = (try? host.pairAccept(timeoutMs: 5000)) ?? ""
      pairExp.fulfill()
    }
    let initJson = try client.pairInitiate(endpoint: addr, code: code, deviceName: "swift-phone", deviceKind: "ios")
    wait(for: [pairExp], timeout: 5.0)

    let initObj = try JSONSerialization.jsonObject(with: Data(initJson.utf8)) as! [String: Any]
    let accObj = try JSONSerialization.jsonObject(with: Data(acceptJson.utf8)) as! [String: Any]
    XCTAssertEqual(initObj["sas"] as? String, accObj["sas"] as? String)
    let devId = accObj["device_id"] as! String

    try host.confirmPeer(peerId: devId, sas: accObj["sas"] as? String)
    try client.confirmPeer(peerId: "swift-host", sas: initObj["sas"] as? String)
    let grantJson = try host.mintGrant(peerId: devId, capsJson: "[\"fs.read\"]", ttlSecs: 3600)

    let sessExp = expectation(description: "session accept")
    var hostSess: TendrilSession?
    pairQueue.async {
      hostSess = try? host.acceptSession(timeoutMs: 5000)
      sessExp.fulfill()
    }
    let cliSess = try client.connect(endpoint: addr, targetHostId: "swift-host", grantJson: grantJson)
    wait(for: [sessExp], timeout: 5.0)
    let srvSess = try XCTUnwrap(hostSess)
    defer {
      cliSess.free()
      srvSess.free()
    }

    XCTAssertTrue(try srvSess.authorize("fs.read"))
    XCTAssertFalse(try srvSess.authorize("shell.exec"))
    try cliSess.sendData(Data("hello-swift".utf8))
    let evJson = try srvSess.pollEvent(timeoutMs: 2000)
    let evObj = try JSONSerialization.jsonObject(with: Data(evJson.utf8)) as! [String: Any]
    XCTAssertEqual(evObj["event"] as? String, "data")
    try host.revokePeer(peerId: devId)
    XCTAssertFalse(try srvSess.authorize("fs.read"))
    try cliSess.close(code: 1000, reason: "done")
  }

  func testM2mEnrollmentAndReplay() throws {
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
    let anchorSigning = decodeB64Url(anchorInfo["signing_pub"] as! String)

    try host.addTrustAnchor(anchorId: "swift-m2m-anchor", signingPub: anchorSigning)
    let addr = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let tokJson = try anchor.mintEnrollmentToken(targetHostId: "swift-m2m-host", subject: nil, ttlSecs: 900)

    let queue = DispatchQueue(label: "tendril.swift.m2m")
    let pairExp = expectation(description: "m2m accept")
    var accJson = ""
    queue.async {
      accJson = (try? host.pairAccept(timeoutMs: 5000)) ?? ""
      pairExp.fulfill()
    }
    let initJson = try client.enrollInitiate(
      endpoint: addr,
      hostId: "swift-m2m-host",
      hostStaticPub: hostStatic,
      hostSigningPub: hostSigning,
      tokenJson: tokJson
    )
    wait(for: [pairExp], timeout: 5.0)
    let initObj = try JSONSerialization.jsonObject(with: Data(initJson.utf8)) as! [String: Any]
    let accObj = try JSONSerialization.jsonObject(with: Data(accJson.utf8)) as! [String: Any]
    XCTAssertEqual(initObj["status"] as? String, "active")
    XCTAssertEqual(accObj["status"] as? String, "active")

    let repExp = expectation(description: "m2m replay accept")
    queue.async {
      _ = try? host.pairAccept(timeoutMs: 5000)
      repExp.fulfill()
    }
    XCTAssertThrowsError(
      try client.enrollInitiate(
        endpoint: addr,
        hostId: "swift-m2m-host",
        hostStaticPub: hostStatic,
        hostSigningPub: hostSigning,
        tokenJson: tokJson
      )
    )
    wait(for: [repExp], timeout: 5.0)
  }
}

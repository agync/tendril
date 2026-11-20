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
}

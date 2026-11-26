import Foundation
import Testing
import CTendril
@testable import Tendril
#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
#endif

/// Replays spec/vectors/routes.json through the Swift binding. The structure mirrors the Python
/// and Node suites: every section is covered or skipped with a reason, and a new section or a
/// new pairing_route_check case field fails the suite until it is handled.
private enum RoutesVectors {
  static let coveredSections: Set<String> = ["pairing_route_statement", "pairing_route_check"]
  static let skippedSections: [String: String] = [
    "route_set": "tendril.h has no verify_route_set, so the Swift binding cannot check route set "
      + "signatures or decode rejections. The section still supplies the pinned host keys.",
    "session_hello_route_seq":
      "SessionHello is built inside the core handshake; no binding exposes the wire JSON.",
  ]
  /// Cases whose URI names a host key the pinned vector host does not hold, so the offline apply
  /// path can only report that no paired host matches.
  /// - route_key_rotated, route_key_rotated_stale_rs: the URI carries the pre-rotation key.
  ///   Following the rotation needs a RotationRecord, which no binding API or vector exposes.
  /// - unchained_key: a pin_ok=false handshake outcome; the apply path sees only a host that is
  ///   not paired.
  static let noHostMatchCases: Set<String> = [
    "route_key_rotated", "route_key_rotated_stale_rs", "unchained_key",
  ]
  /// Case fields the offline apply path does not model. A new field must fail the field test
  /// until it is covered or listed here with a reason.
  static let coveredCaseFields: Set<String> = ["name", "uri", "route_check"]
  static let handshakeOnlyFields: [String: String] = [
    "pin_ok": "outcome of the host key pin check in the pairing handshake",
    "commit_error": "error raised when the handshake commits the pairing",
    "relay_pub_ok": "rp relay key check, made by the pairing initiator against the dialed relay",
    "operator_relay_key_hex": "operator relay key given to the pairing initiator",
    "responder": "which identity answers the handshake in the replay",
    "wires": "wire versions the handshake replay runs on",
    "presented_static_pub_hex": "key material the responder presents in the handshake",
    "presented_ed25519_pub_hex": "key material the responder presents in the handshake",
    "presented_signing_pub_sha256_hex": "key material the responder presents in the handshake",
    "presented_rotation_seq": "rotation chain length the responder presents in the handshake",
  ]

  static let doc: [String: Any] = {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("spec")
      .appendingPathComponent("vectors")
      .appendingPathComponent("routes.json")
    let data = try! Data(contentsOf: url)
    return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
  }()

  static var routeSet: [String: Any] { doc["route_set"] as! [String: Any] }
  static var statement: [String: Any] { doc["pairing_route_statement"] as! [String: Any] }
  static var checkCases: [[String: Any]] {
    (doc["pairing_route_check"] as! [String: Any])["cases"] as! [[String: Any]]
  }

  static func hex(_ s: String) -> Data {
    var out = Data()
    var index = s.startIndex
    while index < s.endIndex {
      let next = s.index(index, offsetBy: 2)
      out.append(UInt8(s[index..<next], radix: 16)!)
      index = next
    }
    return out
  }

  static func b64url(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func query(_ uri: String, _ name: String) -> String? {
    URLComponents(string: uri)?.queryItems?.first { $0.name == name }?.value
  }
}

@Suite
struct TendrilRoutesVectorsCoverageTests {
  @Test
  func everySectionIsCoveredOrExplicitlySkipped() {
    let known = RoutesVectors.coveredSections.union(RoutesVectors.skippedSections.keys)
    #expect(Set(RoutesVectors.doc.keys) == known)
    #expect(RoutesVectors.coveredSections.isDisjoint(with: RoutesVectors.skippedSections.keys))
    #expect(RoutesVectors.skippedSections.values.allSatisfy { !$0.isEmpty })
  }

  @Test
  func everyCheckCaseIsAccountedFor() {
    let names = Set(RoutesVectors.checkCases.map { $0["name"] as! String })
    #expect(RoutesVectors.noHostMatchCases.isSubset(of: names))
  }

  @Test
  func everyCheckCaseFieldIsCoveredOrHandshakeOnly() {
    #expect(RoutesVectors.handshakeOnlyFields.values.allSatisfy { !$0.isEmpty })
    #expect(RoutesVectors.coveredCaseFields.isDisjoint(with: RoutesVectors.handshakeOnlyFields.keys))
    let known = RoutesVectors.coveredCaseFields.union(RoutesVectors.handshakeOnlyFields.keys)
    for c in RoutesVectors.checkCases {
      let extra = Set(c.keys).subtracting(known)
      #expect(extra.isEmpty, "\((c["name"] as? String) ?? "?"): unexpected fields \(extra)")
    }
  }

  @Test
  func vectorHostKeysMatchTheStatementUri() {
    let keys = RoutesVectors.routeSet
    let sh = RoutesVectors.hex(keys["sh_hex"] as! String)
    #expect(RoutesVectors.query(RoutesVectors.statement["uri"] as! String, "sh") == RoutesVectors.b64url(sh))
  }
}

#if canImport(CryptoKit) && canImport(Security)
@Suite
struct TendrilRoutesVectorsReplayTests {
  private let keys = RoutesVectors.routeSet

  private struct Vault {
    let root: URL
    let client: TendrilEndpoint
    let hostId: String
  }

  /// A fresh sealed client whose roster pins the vector host, so every URI carries the same `rq`.
  /// The roster is seeded through the legacy `roster.sealed` migration hook of the sealed open
  /// path, the only way to hand a sealed Swift endpoint a roster built from raw key material
  /// (pairing needs a live handshake). If that hook changes, this helper must follow it.
  private func makeClient() throws -> Vault {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("tendril-swift-rv-\(UUID().uuidString)")
    var handedOver = false
    defer {
      if !handedOver { try? fm.removeItem(at: root) }
    }
    let key = SymmetricKey(size: .bits256)
    let kc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "rv") { key }

    let identityDir = root.appendingPathComponent("identity")
    try TendrilEndpoint(stateDir: identityDir.path, keychainStore: kc).close()
    let identity = try #require(
      try SealedSwiftStateStore(dirPath: identityDir.path, keychain: kc).loadIdentityJson())

    let staticPub = RoutesVectors.hex(keys["static_pub_hex"] as! String)
    let signingPub = RoutesVectors.hex(keys["signing_pub_hex"] as! String)
    let hostId = try TendrilCrypto.deviceId(staticPub: staticPub)
    let roster: [String: Any] = [
      "entries": [
        hostId: [
          "device_id": hostId,
          "name": "vector-host",
          "kind": "host",
          "static_pub": staticPub.map { Int($0) },
          "signing_pub": RoutesVectors.b64url(signingPub),
          "rotation_seq": 0,
          "state": "active",
          "min_wire_version": 1,
        ] as [String: Any]
      ],
      "crls": [String: Any](),
    ]
    let rosterData = try JSONSerialization.data(withJSONObject: roster)

    let dir = root.appendingPathComponent("client")
    try SealedSwiftStateStore(dirPath: dir.path, keychain: kc).saveIdentityJson(identity)
    try kc.sealState(rosterData, authenticating: Data("tendril.roster.v1".utf8))
      .write(to: dir.appendingPathComponent("roster.sealed"))
    let client = try TendrilEndpoint(stateDir: dir.path, keychainStore: kc)
    handedOver = true
    return Vault(root: root, client: client, hostId: hostId)
  }

  private func cleanUp(_ vault: Vault) {
    vault.client.close()
    try? FileManager.default.removeItem(at: vault.root)
  }

  private func obj(_ json: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
  }

  private func signedRoutes(_ vault: Vault) throws -> [String] {
    let view = try obj(vault.client.peerRoutes(peerId: vault.hostId))
    return (view["routes"] as! [[String: Any]])
      .filter { $0["source"] as? String == "signed" }
      .map { $0["hint"] as! String }
  }

  /// The message of the FFI error `body` raises, or a recorded failure when it does not throw one.
  private func ffiMessage(_ body: () throws -> Void) -> String {
    do {
      try body()
      Issue.record("expected an FFI error")
      return ""
    } catch TendrilError.ffi(_, let message) {
      return message
    } catch {
      Issue.record("unexpected error \(error)")
      return ""
    }
  }

  @Test
  func pairingRouteStatementAppliesItsHints() throws {
    let vault = try makeClient()
    defer { cleanUp(vault) }
    let stmt = RoutesVectors.statement
    let applied = try obj(vault.client.applyRouteUri(stmt["uri"] as! String))
    #expect(applied["peer_id"] as? String == vault.hostId)
    #expect(applied["applied"] as? Bool == true)
    #expect(applied["reason"] is NSNull)
    #expect(applied["route_seq"] as? Int == stmt["route_seq"] as? Int)
    let signed = try signedRoutes(vault)
    #expect(signed == (stmt["hints"] as! [String]))
  }

  @Test
  func pairingRouteStatementWithTamperedRqIsRejected() throws {
    let vault = try makeClient()
    defer { cleanUp(vault) }
    let uri = RoutesVectors.statement["uri"] as! String
    let tampered = uri.replacingOccurrences(of: "&rq=7", with: "&rq=8")
    #expect(tampered != uri)
    let message = ffiMessage { _ = try vault.client.applyRouteUri(tampered) }
    #expect(message.contains("does not verify"), "\(message)")
    let signed = try signedRoutes(vault)
    #expect(signed.isEmpty)
  }

  @Test
  func pairingRouteCheckOutcomes() throws {
    let hostK = RoutesVectors.b64url(RoutesVectors.hex(keys["static_pub_hex"] as! String))
    #expect(!RoutesVectors.checkCases.isEmpty)
    for c in RoutesVectors.checkCases {
      try replayCheckCase(c, hostK: hostK)
    }
  }

  private func replayCheckCase(_ c: [String: Any], hostK: String) throws {
    let name = c["name"] as! String
    let uri = c["uri"] as! String
    let vault = try makeClient()
    defer { cleanUp(vault) }
    let uriK = RoutesVectors.query(uri, "k")
    if RoutesVectors.noHostMatchCases.contains(name) {
      #expect(uriK != hostK, "\(name)")
      let message = ffiMessage { _ = try vault.client.applyRouteUri(uri) }
      #expect(message.contains("no paired host matches"), "\(name): \(message)")
      return
    }
    #expect(uriK == hostK, "\(name)")
    switch c["route_check"] as! String {
    case "verified":
      let applied = try obj(vault.client.applyRouteUri(uri))
      #expect(applied["applied"] as? Bool == true, "\(name)")
      let signed = try signedRoutes(vault)
      #expect(!signed.isEmpty, "\(name)")
    case "unsigned":
      let message = ffiMessage { _ = try vault.client.applyRouteUri(uri) }
      #expect(message.contains("not host-signed"), "\(name): \(message)")
    case "invalid":
      let message = ffiMessage { _ = try vault.client.applyRouteUri(uri) }
      #expect(message.contains("does not verify"), "\(name): \(message)")
    default:
      Issue.record("\(name): unknown route_check \(c["route_check"] ?? "nil")")
    }
  }
}
#endif

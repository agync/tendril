import Dispatch
import Foundation
import Testing
import CTendril
@testable import Tendril

#if os(macOS) || os(Linux)

private func onDedicatedThread(_ body: @escaping @Sendable () -> Void) {
  Thread(block: body).start()
}

private final class Box<T>: @unchecked Sendable {
  private let lock = NSLock()
  private var value: T

  init(_ value: T) { self.value = value }

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

private func obj(_ json: String) throws -> [String: Any] {
  try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
}

/// A host and a client paired over loopback, with the client holding a grant. Peers are
/// confirmed, so the host knows the client's device.
private struct RefusalPair {
  let host: TendrilEndpoint
  let client: TendrilEndpoint
  let hostId: String
  let peerId: String
  let grant: String

  func close() {
    host.close()
    client.close()
  }

  /// Runs `connect` on this thread while the host accepts on its own thread, as a refused
  /// connect needs the host to write its notice. Returns the connect outcome.
  func connectWhileAccepting(
    wire: Int,
    _ connect: () throws -> TendrilSession
  ) -> Result<TendrilSession, Error> {
    let accepted = Box<TendrilSession?>(nil)
    let sem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      accepted.set(
        try? (wire == 2 ? host.acceptV2(timeoutMs: 4000) : host.acceptSession(timeoutMs: 4000)))
      sem.signal()
    }
    let outcome = Result { try connect() }
    _ = sem.wait(timeout: .now() + 10.0)
    accepted.get()?.free()
    return outcome
  }
}

private func makePair(wire: Int) throws -> RefusalPair {
  let hostId = "swift-refusal-host-\(wire)"
  let host = try TendrilEndpoint(hostId: hostId)
  let client = try TendrilEndpoint(hostId: "swift-refusal-client-\(wire)")
  _ = try host.serveDirect(listenAddr: "127.0.0.1:0")
  let issued = try obj(host.issuePairingUri())
  let hostBox = Box<String>("")
  let sem = DispatchSemaphore(value: 0)
  onDedicatedThread {
    hostBox.set(
      (try? (wire == 2 ? host.pairV2Accept(timeoutMs: 15_000) : host.pairAccept(timeoutMs: 15_000)))
        ?? "")
    sem.signal()
  }
  let uri = issued["uri"] as! String
  _ =
    wire == 2
    ? try client.pairV2Uri(uri, name: "swift-refusal")
    : try client.pairUri(uri, name: "swift-refusal")
  #expect(sem.wait(timeout: .now() + 15.0) == .success)
  let hostRes = try obj(hostBox.get())
  let peerId = hostRes["device_id"] as! String
  try host.confirmPeer(peerId: peerId, sas: hostRes["sas"] as? String)
  let grant = try host.mintGrant(peerId: peerId, capsJson: "[\"fs.read\"]", ttlSecs: 3600)
  return RefusalPair(host: host, client: client, hostId: hostId, peerId: peerId, grant: grant)
}

@Suite
struct TendrilRefusalTests {
  @Test
  func refusalMapsStableCodesAndCloseCodes() {
    #expect(TendrilRefusal(code: "refused_revoked") == .revoked)
    #expect(TendrilRefusal(code: "refused_pending") == .pending)
    #expect(TendrilRefusal(code: "refused") == .other(0))
    #expect(TendrilRefusal(code: "host_key_unverified") == nil)
    #expect(TendrilRefusal(code: "") == nil)
    #expect(TendrilRefusal.revoked.closeCode == 4001)
    #expect(TendrilRefusal.pending.closeCode == 4004)
    #expect(TendrilRefusal.other(4410).closeCode == 4410)
    #expect(TendrilRefusal.revoked.code == "refused_revoked")
    #expect(TendrilRefusal.pending.code == "refused_pending")
    #expect(TendrilRefusal.other(4410).code == "refused")
  }

  @Test
  func closedEventCarriesTheRefusal() {
    func event(_ fields: String) -> String { "{\"event\":\"closed\"\(fields)}" }
    #expect(
      TendrilRefusal(closedEventJson: event(",\"code\":4001,\"reason\":\"\",\"refusal\":\"revoked\""))
        == .revoked)
    #expect(
      TendrilRefusal(closedEventJson: event(",\"code\":4004,\"refusal\":\"pending\"")) == .pending)
    #expect(
      TendrilRefusal(closedEventJson: event(",\"code\":4410,\"refusal\":\"other\""))
        == .other(4410))
    #expect(TendrilRefusal(closedEventJson: event(",\"code\":1000,\"refusal\":null")) == nil)
    #expect(TendrilRefusal(closedEventJson: event(",\"code\":1000")) == nil)
    #expect(
      TendrilRefusal(closedEventJson: "{\"event\":\"data\",\"refusal\":\"revoked\"}") == nil)
    #expect(TendrilRefusal(closedEventJson: "not json") == nil)
  }

  @Test
  func refusedConnectV2IsATypedError() throws {
    let p = try makePair(wire: 2)
    defer { p.close() }
    try p.host.revokePeer(peerId: p.peerId)
    let outcome = p.connectWhileAccepting(wire: 2) {
      try p.client.connectV2(targetHostId: p.hostId, grantJson: p.grant)
    }
    guard case .failure(let error) = outcome else {
      Issue.record("a revoked peer connected")
      return
    }
    #expect((error as? TendrilError) == .refused(.revoked))
  }

  @Test
  func refusedConnectWithOptionsWire2IsATypedError() throws {
    let p = try makePair(wire: 2)
    defer { p.close() }
    try p.host.revokePeer(peerId: p.peerId)
    let outcome = p.connectWhileAccepting(wire: 2) {
      try p.client.connectWithOptions(targetHostId: p.hostId, wire: 2, grantJson: p.grant)
    }
    guard case .failure(let error) = outcome else {
      Issue.record("a revoked peer connected")
      return
    }
    #expect((error as? TendrilError) == .refused(.revoked))
  }

  @Test
  func refusedV1RefusalSurfacesAfterConnect() throws {
    let p = try makePair(wire: 1)
    defer { p.close() }
    try p.host.revokePeer(peerId: p.peerId)
    let accepted = Box<TendrilSession?>(nil)
    let sem = DispatchSemaphore(value: 0)
    onDedicatedThread {
      accepted.set(try? p.host.acceptSession(timeoutMs: 4000))
      sem.signal()
    }
    let cli = try p.client.connect(targetHostId: p.hostId, grantJson: p.grant)
    defer {
      cli.free()
      _ = sem.wait(timeout: .now() + 10.0)
      accepted.get()?.free()
    }
    var closed: String?
    let deadline = Date().addingTimeInterval(10)
    while closed == nil && Date() < deadline {
      do {
        let ev = try cli.pollEvent(timeoutMs: 500)
        if (try obj(ev))["event"] as? String == "closed" { closed = ev }
      } catch TendrilError.wouldBlock {
        continue
      }
    }
    let ev = try #require(closed)
    let fields = try obj(ev)
    #expect(fields["refusal"] as? String == "revoked")
    #expect(fields["code"] as? Int == 4001)
    #expect(TendrilRefusal(closedEventJson: ev) == .revoked)
    #expect(TendrilRefusal(closedEventJson: "{\"event\":\"closed\",\"code\":1000}") == nil)
    #expect(throws: TendrilError.refused(.revoked)) { try cli.sendData(Data("x".utf8)) }
    #expect(throws: TendrilError.refused(.revoked)) { try cli.rekey() }
    #expect(throws: TendrilError.refused(.revoked)) { try cli.close() }
  }

  @Test
  func refusalEndpointCalls() throws {
    // A silent revoke records no notice, so the refusal is not typed.
    do {
      let p = try makePair(wire: 2)
      defer { p.close() }
      try p.host.revokePeer(peerId: p.peerId, notify: false)
      let outcome = p.connectWhileAccepting(wire: 2) {
        try p.client.connectV2(targetHostId: p.hostId, grantJson: p.grant)
      }
      guard case .failure(let error) = outcome else {
        Issue.record("a silently revoked peer connected")
        return
      }
      if case TendrilError.refused = error { Issue.record("a silent revoke refused: \(error)") }
    }
    // A policy with a zero notice lifetime records no notice at revocation.
    do {
      let p = try makePair(wire: 2)
      defer { p.close() }
      try p.host.setRefusalPolicy(pending: true, revokedNoticeTtlSecs: 0)
      try p.host.revokePeer(peerId: p.peerId)
      let outcome = p.connectWhileAccepting(wire: 2) {
        try p.client.connectV2(targetHostId: p.hostId, grantJson: p.grant)
      }
      guard case .failure(let error) = outcome else {
        Issue.record("a revoked peer connected")
        return
      }
      if case TendrilError.refused = error { Issue.record("ttl 0 recorded a notice: \(error)") }
    }
    // A cleared notice stops the refusal while the peer stays revoked.
    do {
      let p = try makePair(wire: 2)
      defer { p.close() }
      try p.host.revokePeer(peerId: p.peerId)
      try p.host.clearRefusalNotice(p.peerId)
      let outcome = p.connectWhileAccepting(wire: 2) {
        try p.client.connectV2(targetHostId: p.hostId, grantJson: p.grant)
      }
      guard case .failure(let error) = outcome else {
        Issue.record("a revoked peer connected")
        return
      }
      if case TendrilError.refused = error { Issue.record("a cleared notice refused: \(error)") }
      #expect(throws: Error.self) { try p.host.clearRefusalNotice("no-such-peer") }
      #expect(throws: Error.self) { try p.host.revokePeer(peerId: "no-such-peer", notify: true) }
    }
  }

  /// The refusal is read on the thread of the failing call. Threads issuing other FFI calls at
  /// the same time must never see or clear it.
  @Test
  func refusedErrorSurvivesConcurrentFFICalls() throws {
    for _ in 0..<3 {
      let p = try makePair(wire: 2)
      defer { p.close() }
      try p.host.revokePeer(peerId: p.peerId)
      let stop = Box(false)
      let noise = DispatchGroup()
      for _ in 0..<4 {
        noise.enter()
        onDedicatedThread {
          while !stop.get() {
            _ = try? p.client.infoJson()
            _ = try? TendrilCrypto.deviceId(staticPub: Data(repeating: 0, count: 32))
          }
          noise.leave()
        }
      }
      let outcome = p.connectWhileAccepting(wire: 2) {
        try p.client.connectV2(targetHostId: p.hostId, grantJson: p.grant)
      }
      stop.set(true)
      noise.wait()
      guard case .failure(let error) = outcome else {
        Issue.record("a revoked peer connected")
        return
      }
      #expect((error as? TendrilError) == .refused(.revoked))
    }
  }
}

#endif

import CTendril
import Foundation

#if canImport(CoreFoundation)
import CoreFoundation
#endif

#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security
#endif

#if canImport(NetworkExtension) && (os(iOS) || os(visionOS))
import NetworkExtension
#endif

#if canImport(BackgroundTasks) && (os(iOS) || os(tvOS) || os(visionOS))
import BackgroundTasks
#endif

private struct UncheckedSendableBox<T>: @unchecked Sendable {
  let value: T
}

private final class WeakSendableBox<T: AnyObject>: @unchecked Sendable {
  weak var value: T?

  init(_ value: T) {
    self.value = value
  }
}

/// Parsed opaque wake payload (`{"v": 1, "wake_tag": "...", "epoch_s": ...}`).
public struct TendrilWakePayload: Codable, Equatable, Sendable {
  internal static let wakeEpochSecs: UInt64 = 3_600

  public let v: Int
  public let wakeTag: String
  public let epochS: UInt64

  enum CodingKeys: String, CodingKey {
    case v
    case wakeTag = "wake_tag"
    case epochS = "epoch_s"
  }

  public init(v: Int = 1, wakeTag: String, epochS: UInt64) throws {
    guard v == 1, !wakeTag.isEmpty, epochS % Self.wakeEpochSecs == 0 else {
      throw TendrilError.invalidArgument("invalid tendril wake payload")
    }
    self.v = v
    self.wakeTag = wakeTag
    self.epochS = epochS
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let v = try container.decode(Int.self, forKey: .v)
    let wakeTag = try container.decode(String.self, forKey: .wakeTag)
    let epochS = try container.decode(UInt64.self, forKey: .epochS)
    try self.init(v: v, wakeTag: wakeTag, epochS: epochS)
  }

  public init(userInfo: [AnyHashable: Any]) throws {
    let parsedV = try Self.parseUnsignedInt(userInfo["v"], field: "v")
    guard parsedV == 1 else {
      throw TendrilError.invalidArgument("unsupported wake payload version")
    }
    guard let wakeTag = userInfo["wake_tag"] as? String, !wakeTag.isEmpty else {
      throw TendrilError.invalidArgument("missing or invalid wake_tag")
    }
    let epochS = try Self.parseUnsignedInt(userInfo["epoch_s"], field: "epoch_s")
    try self.init(v: 1, wakeTag: wakeTag, epochS: epochS)
  }

  internal func isWithinEpochWindow(nowUnixSecs: UInt64) -> Bool {
    guard epochS % Self.wakeEpochSecs == 0 else {
      return false
    }
    let nowBucket = nowUnixSecs / Self.wakeEpochSecs
    let payloadBucket = epochS / Self.wakeEpochSecs
    let minBucket = nowBucket > 0 ? nowBucket - 1 : 0
    let maxBucket = nowBucket == UInt64.max ? UInt64.max : nowBucket + 1
    return payloadBucket >= minBucket && payloadBucket <= maxBucket
  }

  private static func parseUnsignedInt(_ raw: Any?, field: String) throws -> UInt64 {
    guard let raw else {
      throw TendrilError.invalidArgument("missing \(field) in wake payload")
    }
    #if canImport(CoreFoundation)
    if let num = raw as? NSNumber {
      if CFGetTypeID(num) == CFBooleanGetTypeID() {
        throw TendrilError.invalidArgument("invalid \(field) in wake payload")
      }
      if CFNumberIsFloatType(num as CFNumber) {
        throw TendrilError.invalidArgument("invalid \(field) in wake payload")
      }
      if num.stringValue.hasPrefix("-") {
        throw TendrilError.invalidArgument("invalid \(field) in wake payload")
      }
      let d = num.doubleValue
      if !d.isFinite || d < 0 || d.rounded(.towardZero) != d {
        throw TendrilError.invalidArgument("invalid \(field) in wake payload")
      }
      let u = num.uint64Value
      if NSNumber(value: u) == num {
        return u
      }
      throw TendrilError.invalidArgument("invalid \(field) in wake payload")
    }
    #endif
    if raw is Bool || raw is Double || raw is Float {
      throw TendrilError.invalidArgument("invalid \(field) in wake payload")
    }
    if let u = raw as? UInt64 {
      return u
    }
    if let i = raw as? Int, i >= 0 {
      return UInt64(i)
    }
    throw TendrilError.invalidArgument("invalid \(field) in wake payload")
  }
}

public struct TendrilWakePeer: Sendable {
  public let peerId: String
  public let wakeSecret: Data
  public let grantJson: String?

  public init(peerId: String, wakeSecret: Data, grantJson: String? = nil) {
    self.peerId = peerId
    self.wakeSecret = wakeSecret
    self.grantJson = grantJson
  }
}

public struct TendrilWakeResult: Equatable, Sendable {
  public let peerId: String
  public let messages: [Data]

  public init(peerId: String, messages: [Data]) {
    self.peerId = peerId
    self.messages = messages
  }
}

internal func decodeBase64Url(_ encoded: String) -> Data? {
  var b64 = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  let rem = b64.count % 4
  if rem != 0 {
    b64.append(String(repeating: "=", count: 4 - rem))
  }
  return Data(base64Encoded: b64)
}

#if canImport(CryptoKit) && canImport(Security)
/// Coordinates Notification Service Extension (`UNNotificationServiceExtension`) wake handling.
///
/// Matches incoming `wake_tag` notifications in constant time via Rust `tendril_verify_wake_tag`,
/// opens a compact `.extension` + `clientOnly` endpoint on the shared App Group directory and
/// Keychain Access Group, connects over authenticated `Noise_XXhfs` stored routes (or explicit
/// endpoint in tests), authorizes `requiredCap` before surfacing decrypted frames, and wires
/// `cancel()` for `serviceExtensionTimeWillExpire()`.
public final class TendrilWakeProcessor: @unchecked Sendable {
  private let lock = NSLock()
  private let cleanupQueue = DispatchQueue(label: "dev.tendril.wake.cleanup", qos: .userInitiated)
  private let stateDir: String
  private let hostId: String?
  private let keychainStore: TendrilKeychainStore
  private let peers: [TendrilWakePeer]
  private let requiredCap: String
  private let wire: Int
  private let transportConfigJson: String?
  private let mldsaSigner: (any TendrilMlDsa65Provider)?
  private let budgetSecs: TimeInterval
  private var activeEndpoint: TendrilEndpoint?
  private var activeSession: TendrilSession?
  private var cancelled = false

  public init(
    stateDir: String,
    hostId: String? = nil,
    keychainConfiguration: TendrilKeychainConfiguration = TendrilKeychainConfiguration(),
    keychainStore: TendrilKeychainStore? = nil,
    peers: [TendrilWakePeer],
    requiredCap: String,
    wire: Int = 2,
    transportConfigJson: String? = nil,
    mldsaSigner: (any TendrilMlDsa65Provider)? = nil,
    budgetSecs: TimeInterval = 20.0
  ) throws {
    guard !requiredCap.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw TendrilError.invalidArgument("requiredCap must not be empty")
    }
    self.stateDir = stateDir
    self.hostId = hostId
    self.keychainStore = keychainStore ?? TendrilKeychainStore(configuration: keychainConfiguration)
    self.peers = peers
    self.requiredCap = requiredCap
    self.wire = wire
    self.transportConfigJson = transportConfigJson
    self.mldsaSigner = mldsaSigner
    self.budgetSecs = max(0.5, budgetSecs)
  }

  public static func matchPeer(
    payload: TendrilWakePayload,
    peers: [(peerId: String, wakeSecret: Data)],
    nowUnixSecs: UInt64 = UInt64(max(0, Int64(Date().timeIntervalSince1970)))
  ) throws -> String? {
    for peer in peers {
      if try TendrilCrypto.verifyWakeTag(
        secret: peer.wakeSecret,
        tagB64: payload.wakeTag,
        nowUnixSecs: nowUnixSecs
      ) {
        return peer.peerId
      }
    }
    return nil
  }

  public func cancel() {
    lock.lock()
    cancelled = true
    let sess = activeSession
    let ep = activeEndpoint
    activeSession = nil
    activeEndpoint = nil
    lock.unlock()

    if sess != nil || ep != nil {
      cleanupQueue.async {
        sess?.free()
        ep?.close()
      }
    }
  }

  public func process(
    userInfo: [AnyHashable: Any],
    nowUnixSecs: UInt64 = UInt64(max(0, Int64(Date().timeIntervalSince1970))),
    endpointOverride: String? = nil,
    maxMessages: Int = 16,
    onMessage: (@Sendable (String, Data) throws -> Void)? = nil
  ) throws -> TendrilWakeResult? {
    let payload = try TendrilWakePayload(userInfo: userInfo)
    guard payload.isWithinEpochWindow(nowUnixSecs: nowUnixSecs) else {
      throw TendrilError.invalidArgument("wake payload epoch_s outside active window")
    }
    var matchedPeer: TendrilWakePeer?
    for peer in peers {
      if try TendrilCrypto.verifyWakeTag(
        secret: peer.wakeSecret,
        tagB64: payload.wakeTag,
        nowUnixSecs: nowUnixSecs
      ) {
        matchedPeer = peer
        break
      }
    }
    guard let matched = matchedPeer else {
      return nil
    }

    lock.lock()
    let alreadyCancelled = cancelled
    lock.unlock()
    if alreadyCancelled {
      throw TendrilError.closed
    }

    let options = TendrilEndpointOptions(
      runtimeProfile: .extension,
      clientOnly: true,
      mldsaSigner: mldsaSigner,
      powerProfile: .lowPower
    )
    let ep = try TendrilEndpoint(
      stateDir: stateDir,
      hostId: hostId,
      keychainStore: keychainStore,
      options: options
    )
    lock.lock()
    if cancelled {
      lock.unlock()
      ep.close()
      throw TendrilError.closed
    }
    activeEndpoint = ep
    lock.unlock()

    defer {
      lock.lock()
      let sess = activeSession
      activeSession = nil
      if activeEndpoint === ep {
        activeEndpoint = nil
      }
      lock.unlock()
      sess?.free()
      ep.close()
    }

    if let transportConfigJson {
      try ep.configureTransportsJSON(transportConfigJson)
    }

    let sess = try ep.connectWithOptions(
      targetHostId: matched.peerId,
      wire: wire,
      grantJson: matched.grantJson,
      endpoint: endpointOverride
    )
    lock.lock()
    if cancelled {
      lock.unlock()
      sess.free()
      throw TendrilError.closed
    }
    activeSession = sess
    lock.unlock()

    let allowed = try sess.authorize(requiredCap)
    guard allowed else {
      throw TendrilError.ffi(
        code: TENDRIL_ERR_PROTOCOL.rawValue,
        message: "capability not authorized"
      )
    }

    var messages: [Data] = []
    let deadline = Date().addingTimeInterval(budgetSecs)
    let limit = max(1, maxMessages)

    while messages.count < limit && Date() < deadline {
      lock.lock()
      let isCancelled = cancelled
      lock.unlock()
      if isCancelled {
        throw TendrilError.closed
      }

      let remainingMs = UInt64(max(1.0, deadline.timeIntervalSinceNow * 1000.0))
      let pollMs: UInt64 = messages.isEmpty ? min(500, remainingMs) : min(50, remainingMs)

      let rawEvent: String
      do {
        rawEvent = try sess.pollEvent(timeoutMs: pollMs)
      } catch TendrilError.wouldBlock {
        if !messages.isEmpty {
          break
        }
        continue
      } catch TendrilError.eof {
        break
      }

      guard let obj = try JSONSerialization.jsonObject(with: Data(rawEvent.utf8)) as? [String: Any],
        let kind = obj["event"] as? String
      else {
        continue
      }
      if kind == "closed" {
        break
      }
      if kind == "data", let b64 = obj["data_b64"] as? String, let payloadData = decodeBase64Url(b64) {
        messages.append(payloadData)
        try onMessage?(matched.peerId, payloadData)
      }
    }

    lock.lock()
    let wasCancelled = cancelled
    lock.unlock()
    if wasCancelled {
      throw TendrilError.closed
    }

    return TendrilWakeResult(peerId: matched.peerId, messages: messages)
  }
}

#if canImport(NetworkExtension) && (os(iOS) || os(visionOS))
/// Coordinator for `NEAppPushProvider` subclasses maintaining an authenticated Wire v2 control
/// session over an explicit LAN relay endpoint in the `.extension` + `clientOnly` runtime profile.
@available(iOS 14.0, visionOS 1.0, *)
public final class TendrilLocalPushSession: @unchecked Sendable {
  private let lock = NSLock()
  private let queue = DispatchQueue(label: "dev.tendril.local-push", qos: .utility)
  private let stateDir: String
  private let hostId: String?
  private let keychainStore: TendrilKeychainStore
  private let targetHostId: String
  private let relayEndpoint: String
  private let relayHost: String?
  private let grantJson: String?
  private let requiredCap: String
  private let transportConfigJson: String?
  private let mldsaSigner: (any TendrilMlDsa65Provider)?
  private let onPayload: @Sendable (String, Data) -> Void
  private let onError: (@Sendable (Error) -> Void)?

  private var endpoint: TendrilEndpoint?
  private var session: TendrilSession?
  private var runGeneration: UInt64 = 0
  private var running = false
  private var stopped = false

  public init(
    stateDir: String,
    hostId: String? = nil,
    keychainConfiguration: TendrilKeychainConfiguration = TendrilKeychainConfiguration(),
    targetHostId: String,
    relayEndpoint: String,
    relayHost: String? = nil,
    grantJson: String? = nil,
    requiredCap: String,
    transportConfigJson: String? = nil,
    mldsaSigner: (any TendrilMlDsa65Provider)? = nil,
    onPayload: @escaping @Sendable (String, Data) -> Void,
    onError: (@Sendable (Error) -> Void)? = nil
  ) throws {
    guard !requiredCap.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw TendrilError.invalidArgument("requiredCap must not be empty")
    }
    self.stateDir = stateDir
    self.hostId = hostId
    self.keychainStore = TendrilKeychainStore(configuration: keychainConfiguration)
    self.targetHostId = targetHostId
    self.relayEndpoint = relayEndpoint
    self.relayHost = relayHost
    self.grantJson = grantJson
    self.requiredCap = requiredCap
    self.transportConfigJson = transportConfigJson
    self.mldsaSigner = mldsaSigner
    self.onPayload = onPayload
    self.onError = onError
  }

  public func start() {
    lock.lock()
    stopped = false
    let shouldLaunch = !running
    var launchGeneration: UInt64 = 0
    if shouldLaunch {
      running = true
      runGeneration &+= 1
      launchGeneration = runGeneration
    }
    lock.unlock()
    if shouldLaunch {
      queue.async { [weak self] in
        self?.runLoop(generation: launchGeneration)
      }
    }
  }

  public func handleTimer() {
    lock.lock()
    let shouldRestart = !stopped && !running
    var launchGeneration: UInt64 = 0
    if shouldRestart {
      running = true
      runGeneration &+= 1
      launchGeneration = runGeneration
    }
    lock.unlock()
    if shouldRestart {
      queue.async { [weak self] in
        self?.runLoop(generation: launchGeneration)
      }
    }
  }

  public func stop(
    with reason: NEProviderStopReason = .userInitiated,
    completionHandler: (@Sendable () -> Void)? = nil
  ) {
    _ = reason
    lock.lock()
    stopped = true
    running = false
    runGeneration &+= 1
    let activeSess = session
    let activeEp = endpoint
    session = nil
    endpoint = nil
    lock.unlock()

    activeSess?.free()
    activeEp?.close()
    completionHandler?()
  }

  private func runLoop(generation: UInt64) {
    defer {
      lock.lock()
      let isCurrent = runGeneration == generation
      let activeSess = isCurrent ? session : nil
      let activeEp = isCurrent ? endpoint : nil
      if isCurrent {
        session = nil
        endpoint = nil
        running = false
      }
      lock.unlock()
      activeSess?.free()
      activeEp?.close()
    }

    lock.lock()
    let abortBeforeStart = stopped || runGeneration != generation
    lock.unlock()
    if abortBeforeStart {
      return
    }

    do {
      let ep = try TendrilEndpoint(
        stateDir: stateDir,
        hostId: hostId,
        keychainStore: keychainStore,
        options: TendrilEndpointOptions(
          runtimeProfile: .extension,
          clientOnly: true,
          mldsaSigner: mldsaSigner,
          powerProfile: .lowPower
        )
      )
      lock.lock()
      if stopped || runGeneration != generation {
        lock.unlock()
        ep.close()
        return
      }
      endpoint = ep
      lock.unlock()

      if let transportConfigJson {
        try ep.configureTransportsJSON(transportConfigJson)
      }

      let sess = try ep.connectV2(
        endpoint: relayEndpoint,
        relayHost: relayHost,
        targetHostId: targetHostId,
        grantJson: grantJson
      )
      lock.lock()
      if stopped || runGeneration != generation {
        lock.unlock()
        sess.free()
        return
      }
      session = sess
      lock.unlock()

      guard try sess.authorize(requiredCap) else {
        throw TendrilError.ffi(
          code: TENDRIL_ERR_PROTOCOL.rawValue,
          message: "local push capability not authorized"
        )
      }

      let peerId = try sess.peerId()
      while true {
        lock.lock()
        let shouldContinue = !stopped && runGeneration == generation
        lock.unlock()
        if !shouldContinue { break }

        let rawEvent: String
        do {
          rawEvent = try sess.pollEvent(timeoutMs: 300_000)
        } catch TendrilError.wouldBlock {
          continue
        } catch TendrilError.eof {
          break
        }
        guard let obj = try JSONSerialization.jsonObject(with: Data(rawEvent.utf8)) as? [String: Any],
          let kind = obj["event"] as? String
        else {
          continue
        }
        if kind == "closed" {
          break
        }
        if kind == "data", let b64 = obj["data_b64"] as? String, let payload = decodeBase64Url(b64) {
          onPayload(peerId, payload)
        }
      }
    } catch {
      lock.lock()
      let shouldReportError = !stopped && runGeneration == generation
      lock.unlock()
      if shouldReportError {
        onError?(error)
      }
    }
  }
}
#endif

#if canImport(BackgroundTasks) && (os(iOS) || os(tvOS) || os(visionOS))
/// Coordinator for `BGAppRefreshTask` and `BGProcessingTask` sync loops.
///
/// Opens an `.extension` + `clientOnly` endpoint on the caller's shared directory and Keychain
/// configuration, binds `task.expirationHandler` directly to `endpoint.close()`, and guarantees
/// `task.setTaskCompleted(success:)` is called once.
@available(iOS 13.0, tvOS 13.0, visionOS 1.0, *)
public final class TendrilBackgroundSync: @unchecked Sendable {
  private final class RunState: @unchecked Sendable {
    let lock = NSLock()
    var activeEndpoint: TendrilEndpoint?
    var expired = false
    var completed = false
  }

  private let queue = DispatchQueue(label: "dev.tendril.background-sync", qos: .utility)
  private let cleanupQueue = DispatchQueue(
    label: "dev.tendril.background-sync.cleanup",
    qos: .utility
  )

  public init() {}

  public func run(
    task: BGTask,
    stateDir: String,
    hostId: String? = nil,
    keychainConfiguration: TendrilKeychainConfiguration = TendrilKeychainConfiguration(),
    mldsaSigner: (any TendrilMlDsa65Provider)? = nil,
    work: @escaping @Sendable (TendrilEndpoint) throws -> Void
  ) {
    let taskBox = UncheckedSendableBox(value: task)
    let weakTaskBox = WeakSendableBox(task)
    let runState = RunState()
    let localCleanupQueue = cleanupQueue

    let completeOnce: @Sendable (Bool) -> Void = { success in
      runState.lock.lock()
      let shouldComplete = !runState.completed
      runState.completed = true
      runState.lock.unlock()
      if shouldComplete {
        weakTaskBox.value?.setTaskCompleted(success: success)
      }
    }

    task.expirationHandler = {
      runState.lock.lock()
      runState.expired = true
      let ep = runState.activeEndpoint
      runState.activeEndpoint = nil
      runState.lock.unlock()
      completeOnce(false)
      if let ep {
        localCleanupQueue.async {
          ep.close()
        }
      }
    }

    queue.async {
      var ep: TendrilEndpoint?
      defer {
        _ = taskBox
      }
      do {
        runState.lock.lock()
        let alreadyExpired = runState.expired
        runState.lock.unlock()
        if alreadyExpired {
          completeOnce(false)
          return
        }

        let created = try TendrilEndpoint(
          stateDir: stateDir,
          hostId: hostId,
          keychainStore: TendrilKeychainStore(configuration: keychainConfiguration),
          options: TendrilEndpointOptions(
            runtimeProfile: .extension,
            clientOnly: true,
            mldsaSigner: mldsaSigner,
            powerProfile: .lowPower
          )
        )
        ep = created

        runState.lock.lock()
        if runState.expired {
          runState.lock.unlock()
          created.close()
          completeOnce(false)
          return
        }
        runState.activeEndpoint = created
        runState.lock.unlock()

        try work(created)

        runState.lock.lock()
        if runState.activeEndpoint === created {
          runState.activeEndpoint = nil
        }
        let didExpire = runState.expired
        runState.lock.unlock()
        created.close()
        completeOnce(!didExpire)
      } catch {
        runState.lock.lock()
        if let created = ep, runState.activeEndpoint === created {
          runState.activeEndpoint = nil
        }
        runState.lock.unlock()
        ep?.close()
        completeOnce(false)
      }
    }
  }
}
#endif
#endif

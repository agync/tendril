import Foundation

#if canImport(CryptoKit) && canImport(Security)
#if canImport(CoreFoundation)
import CoreFoundation
#endif
import CryptoKit
#if canImport(Darwin)
import Darwin
#endif
import Security

public enum TendrilCustodyPolicy: Sendable, Equatable {
  case keychainSoftware
  case secureEnclaveOrKeychain
  case secureEnclaveRequired
}

public struct TendrilKeychainConfiguration: Sendable {
  public var service: String
  public var account: String
  public var accessGroup: String?
  public var custody: TendrilCustodyPolicy
  private var accessControlFlagsRawValue: UInt

  public var accessControlFlags: SecAccessControlCreateFlags {
    get {
      SecAccessControlCreateFlags(
        rawValue: SecAccessControlCreateFlags.RawValue(accessControlFlagsRawValue)
      )
    }
    set { accessControlFlagsRawValue = UInt(newValue.rawValue) }
  }

  public init(
    service: String = "dev.tendril.state",
    account: String = "master-key-v1",
    accessGroup: String? = nil,
    custody: TendrilCustodyPolicy = .secureEnclaveOrKeychain,
    accessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
  ) {
    self.service = service
    self.account = account
    self.accessGroup = accessGroup
    self.custody = custody
    self.accessControlFlagsRawValue = UInt(accessControlFlags.rawValue)
  }
}

public enum TendrilKeychainError: Error, Equatable, Sendable {
  case osStatus(OSStatus)
  case invalidData
  case secureEnclaveUnavailable
  case downgradeRejected
}

internal protocol TendrilKeyAgreementPrivateKey: Sendable {
  var publicKeyX963: Data { get }
  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

internal struct SecureEnclaveKeyAgreementAdapter: TendrilKeyAgreementPrivateKey, @unchecked Sendable {
  private let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey

  init(_ privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey) {
    self.privateKey = privateKey
  }

  var publicKeyX963: Data {
    privateKey.publicKey.x963Representation
  }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    try privateKey.sharedSecretFromKeyAgreement(with: publicKeyShare)
  }
}

internal struct SoftwareKeyAgreementAdapter: TendrilKeyAgreementPrivateKey, @unchecked Sendable {
  private let privateKey: P256.KeyAgreement.PrivateKey

  init(_ privateKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()) {
    self.privateKey = privateKey
  }

  var publicKeyX963: Data {
    privateKey.publicKey.x963Representation
  }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    try privateKey.sharedSecretFromKeyAgreement(with: publicKeyShare)
  }
}

public final class TendrilKeychainStore: @unchecked Sendable {
  internal static let formatVersionV1: UInt8 = 1
  internal static let formatVersionV2: UInt8 = 2
  internal static let sepP256AccountSuffix = ".sep-p256"
  internal static let v2CommittedAccountSuffix = ".sep-v2-committed"
  private static let p256X963Length = 65
  private static let domainAadV1 = Data("tendril.state.v1\0".utf8)
  private static let domainAadV2 = Data("tendril.state.v2\0".utf8)
  private static let seWrapInfo = Data("tendril.se.wrap.v1".utf8)
  private static let v2CommittedMarker = Data([formatVersionV2])

  private let lock = NSLock()
  public let configuration: TendrilKeychainConfiguration
  private let customKeyProvider: (@Sendable () throws -> SymmetricKey)?
  private let customEnvelopeProvider: (@Sendable () throws -> any TendrilKeyAgreementPrivateKey)?
  private let v2CommitmentProbe: (@Sendable () throws -> Bool)?
  private var v2CustodyCommitted: Bool = false

  public convenience init(service: String = "dev.tendril.state", account: String = "master-key-v1") {
    self.init(
      configuration: TendrilKeychainConfiguration(service: service, account: account),
      customKeyProvider: nil,
      customEnvelopeProvider: nil,
      v2CommitmentProbe: nil
    )
  }

  public convenience init(configuration: TendrilKeychainConfiguration) {
    self.init(
      configuration: configuration,
      customKeyProvider: nil,
      customEnvelopeProvider: nil,
      v2CommitmentProbe: nil
    )
  }

  internal convenience init(
    service: String = "dev.tendril.state",
    account: String = "master-key-v1",
    customKeyProvider: (@Sendable () throws -> SymmetricKey)?
  ) {
    self.init(
      configuration: TendrilKeychainConfiguration(
        service: service,
        account: account,
        custody: customKeyProvider == nil ? .secureEnclaveOrKeychain : .keychainSoftware
      ),
      customKeyProvider: customKeyProvider,
      customEnvelopeProvider: nil,
      v2CommitmentProbe: nil
    )
  }

  internal init(
    configuration: TendrilKeychainConfiguration = TendrilKeychainConfiguration(),
    customKeyProvider: (@Sendable () throws -> SymmetricKey)? = nil,
    customEnvelopeProvider: (@Sendable () throws -> any TendrilKeyAgreementPrivateKey)? = nil,
    v2CommitmentProbe: (@Sendable () throws -> Bool)? = nil
  ) {
    self.configuration = configuration
    self.customKeyProvider = customKeyProvider
    self.customEnvelopeProvider = customEnvelopeProvider
    self.v2CommitmentProbe = v2CommitmentProbe
  }

  internal var allowsHardwareMlDsaCustody: Bool {
    configuration.custody != .keychainSoftware
      && customKeyProvider == nil
      && customEnvelopeProvider == nil
  }

  public func loadOrCreateMasterKey() throws -> SymmetricKey {
    lock.lock()
    defer { lock.unlock() }
    if let customKeyProvider {
      return try customKeyProvider()
    }
    return try loadOrCreateMasterKeyUnlocked()
  }

  private func loadOrCreateMasterKeyViaProviderOrKeychainUnlocked() throws -> SymmetricKey {
    if let customKeyProvider {
      return try customKeyProvider()
    }
    return try loadOrCreateMasterKeyUnlocked()
  }

  private func loadOrCreateMasterKeyUnlocked() throws -> SymmetricKey {
    if let existing = try readKey() {
      return existing
    }
    let fresh = SymmetricKey(size: .bits256)
    if try storeKey(fresh) {
      return fresh
    }
    if let raced = try readKey() {
      return raced
    }
    throw TendrilKeychainError.osStatus(errSecDuplicateItem)
  }

  private static func combinedAadV1(_ authenticating: Data) -> Data {
    var aad = domainAadV1
    if !authenticating.isEmpty {
      aad.append(authenticating)
    }
    return aad
  }

  private static func combinedAadV2(_ authenticating: Data) -> Data {
    var aad = domainAadV2
    if !authenticating.isEmpty {
      aad.append(authenticating)
    }
    return aad
  }

  internal static func sealV1Envelope(
    _ plaintext: Data,
    using key: SymmetricKey,
    authenticating: Data = Data()
  ) throws -> Data {
    let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: combinedAadV1(authenticating))
    guard let combined = sealed.combined else {
      throw TendrilKeychainError.invalidData
    }
    var out = Data(capacity: 1 + combined.count)
    out.append(formatVersionV1)
    out.append(combined)
    return out
  }

  internal static func openV1Envelope(
    _ combined: Data,
    using key: SymmetricKey,
    authenticating: Data = Data()
  ) throws -> Data {
    guard combined.count > 1, combined[combined.startIndex] == formatVersionV1 else {
      throw TendrilKeychainError.invalidData
    }
    let box = try AES.GCM.SealedBox(combined: combined.dropFirst())
    return try AES.GCM.open(box, using: key, authenticating: combinedAadV1(authenticating))
  }

  internal static func sealV2Envelope(
    _ plaintext: Data,
    using keyAgreementKey: any TendrilKeyAgreementPrivateKey,
    authenticating: Data = Data()
  ) throws -> Data {
    let sepPubX963 = keyAgreementKey.publicKeyX963
    guard sepPubX963.count == p256X963Length else {
      throw TendrilKeychainError.invalidData
    }
    let eph = P256.KeyAgreement.PrivateKey()
    let ephPubX963 = eph.publicKey.x963Representation
    guard ephPubX963.count == p256X963Length else {
      throw TendrilKeychainError.invalidData
    }
    let shared = try keyAgreementKey.sharedSecretFromKeyAgreement(with: eph.publicKey)
    var salt = Data(capacity: ephPubX963.count + sepPubX963.count)
    salt.append(ephPubX963)
    salt.append(sepPubX963)
    let wrapKey = shared.hkdfDerivedSymmetricKey(
      using: SHA256.self,
      salt: salt,
      sharedInfo: seWrapInfo,
      outputByteCount: 32
    )
    let sealed = try AES.GCM.seal(
      plaintext,
      using: wrapKey,
      authenticating: combinedAadV2(authenticating)
    )
    guard let combined = sealed.combined else {
      throw TendrilKeychainError.invalidData
    }
    var out = Data(capacity: 1 + ephPubX963.count + combined.count)
    out.append(formatVersionV2)
    out.append(ephPubX963)
    out.append(combined)
    return out
  }

  internal static func openV2Envelope(
    _ combined: Data,
    using keyAgreementKey: any TendrilKeyAgreementPrivateKey,
    authenticating: Data = Data()
  ) throws -> Data {
    guard combined.count > 1 + p256X963Length, combined[combined.startIndex] == formatVersionV2 else {
      throw TendrilKeychainError.invalidData
    }
    let ephStart = combined.index(after: combined.startIndex)
    let ephEnd = combined.index(ephStart, offsetBy: p256X963Length)
    let ephPubX963 = Data(combined[ephStart..<ephEnd])
    let ephPub = try P256.KeyAgreement.PublicKey(x963Representation: ephPubX963)
    let sepPubX963 = keyAgreementKey.publicKeyX963
    guard sepPubX963.count == p256X963Length else {
      throw TendrilKeychainError.invalidData
    }
    let shared = try keyAgreementKey.sharedSecretFromKeyAgreement(with: ephPub)
    var salt = Data(capacity: ephPubX963.count + sepPubX963.count)
    salt.append(ephPubX963)
    salt.append(sepPubX963)
    let wrapKey = shared.hkdfDerivedSymmetricKey(
      using: SHA256.self,
      salt: salt,
      sharedInfo: seWrapInfo,
      outputByteCount: 32
    )
    let box = try AES.GCM.SealedBox(combined: combined[ephEnd...])
    return try AES.GCM.open(box, using: wrapKey, authenticating: combinedAadV2(authenticating))
  }

  public func sealState(_ plaintext: Data, authenticating: Data = Data()) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    return try sealStateUnlocked(plaintext, authenticating: authenticating, commitV2: true)
  }

  internal func sealStateWithoutCommit(_ plaintext: Data, authenticating: Data = Data()) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    return try sealStateUnlocked(plaintext, authenticating: authenticating, commitV2: false)
  }

  private func sealStateUnlocked(
    _ plaintext: Data,
    authenticating: Data = Data(),
    commitV2: Bool
  ) throws -> Data {
    if let customEnvelopeProvider {
      let seKey = try customEnvelopeProvider()
      let sealed = try Self.sealV2Envelope(plaintext, using: seKey, authenticating: authenticating)
      if commitV2 {
        try persistV2CommitmentMarkerUnlocked()
      }
      return sealed
    }
    if let customKeyProvider {
      try rejectV1IfV2CommittedUnlocked()
      let key = try customKeyProvider()
      return try Self.sealV1Envelope(plaintext, using: key, authenticating: authenticating)
    }

    if configuration.custody == .keychainSoftware {
      try rejectV1IfV2CommittedUnlocked()
      let key = try loadOrCreateMasterKeyUnlocked()
      return try Self.sealV1Envelope(plaintext, using: key, authenticating: authenticating)
    }

    var v2Active = v2CustodyCommitted
    if !v2Active {
      v2Active = try hasCommittedV2MarkerUnlocked()
    }
    if !v2Active {
      v2Active = try hasExistingSepP256KeyUnlocked()
    }
    if v2Active {
      let (seKey, createdNewSep) = try loadOrCreateSepP256KeyUnlocked()
      return try sealV2WithCleanupUnlocked(
        plaintext,
        authenticating: authenticating,
        seKey: seKey,
        createdNewSep: createdNewSep,
        commitV2: commitV2
      )
    }

    guard SecureEnclave.isAvailable else {
      if configuration.custody == .secureEnclaveRequired {
        throw TendrilKeychainError.secureEnclaveUnavailable
      }
      let key = try loadOrCreateMasterKeyUnlocked()
      return try Self.sealV1Envelope(plaintext, using: key, authenticating: authenticating)
    }

    let seKey: any TendrilKeyAgreementPrivateKey
    let createdNewSep: Bool
    do {
      (seKey, createdNewSep) = try loadOrCreateSepP256KeyUnlocked()
    } catch {
      if configuration.custody == .secureEnclaveRequired
        || configuration.accessGroup != nil
        || !Self.isFallbackEntitlementOrAvailabilityError(error)
      {
        throw error
      }
      let key = try loadOrCreateMasterKeyUnlocked()
      return try Self.sealV1Envelope(plaintext, using: key, authenticating: authenticating)
    }
    return try sealV2WithCleanupUnlocked(
      plaintext,
      authenticating: authenticating,
      seKey: seKey,
      createdNewSep: createdNewSep,
      commitV2: commitV2
    )
  }

  private func sealV2WithCleanupUnlocked(
    _ plaintext: Data,
    authenticating: Data,
    seKey: any TendrilKeyAgreementPrivateKey,
    createdNewSep: Bool,
    commitV2: Bool
  ) throws -> Data {
    do {
      let sealed = try Self.sealV2Envelope(plaintext, using: seKey, authenticating: authenticating)
      if commitV2 {
        try persistV2CommitmentMarkerUnlocked()
      }
      return sealed
    } catch {
      if createdNewSep {
        try? Self.deleteGenericItem(
          configuration: configuration,
          accountSuffix: Self.sepP256AccountSuffix,
          isSepOrV2: true
        )
      }
      throw error
    }
  }

  public func openState(_ combined: Data, authenticating: Data = Data()) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    return try openStateUnlocked(combined, authenticating: authenticating, commitV2: true)
  }

  internal func openStateWithoutCommit(_ combined: Data, authenticating: Data = Data()) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    return try openStateUnlocked(combined, authenticating: authenticating, commitV2: false)
  }

  private func openStateUnlocked(
    _ combined: Data,
    authenticating: Data = Data(),
    commitV2: Bool
  ) throws -> Data {
    guard combined.count > 1, let version = combined.first else {
      throw TendrilKeychainError.invalidData
    }
    switch version {
    case Self.formatVersionV1:
      try rejectV1IfV2CommittedUnlocked()
      let key = try loadOrCreateMasterKeyViaProviderOrKeychainUnlocked()
      return try Self.openV1Envelope(combined, using: key, authenticating: authenticating)

    case Self.formatVersionV2:
      let seKey = try resolveExistingSepKeyForOpenUnlocked()
      var plain = try Self.openV2Envelope(combined, using: seKey, authenticating: authenticating)
      if commitV2 {
        do {
          try persistV2CommitmentMarkerUnlocked()
        } catch {
          if !plain.isEmpty {
            plain.resetBytes(in: 0..<plain.count)
          }
          throw error
        }
      }
      return plain

    default:
      throw TendrilKeychainError.invalidData
    }
  }

  /// Phase 1 of transactional `0x01 -> 0x02` upgrade: verifies v2 custody is not yet committed,
  /// decrypts `0x01`, re-seals as `0x02` when Secure Enclave custody is active (reusing an
  /// uncommitted `.sep-p256` left by an interrupted upgrade), and returns the upgraded envelope and
  /// plaintext without committing `.sep-v2-committed` or `v2CustodyCommitted` yet.
  internal func beginUpgradeV1ToV2(
    _ combined: Data,
    authenticating: Data = Data()
  ) throws -> (data: Data, upgraded: Bool, plaintext: Data) {
    lock.lock()
    defer { lock.unlock() }
    guard combined.count > 1, let version = combined.first else {
      throw TendrilKeychainError.invalidData
    }
    if version == Self.formatVersionV2 {
      let plain = try openStateUnlocked(combined, authenticating: authenticating, commitV2: false)
      return (combined, false, plain)
    }
    guard version == Self.formatVersionV1 else {
      throw TendrilKeychainError.invalidData
    }
    try rejectV1IfV2CommittedUnlocked()
    let masterKey = try loadOrCreateMasterKeyViaProviderOrKeychainUnlocked()
    var plain = try Self.openV1Envelope(combined, using: masterKey, authenticating: authenticating)
    do {
      let reSealed = try sealStateUnlocked(plain, authenticating: authenticating, commitV2: false)
      return (reSealed, reSealed.first == Self.formatVersionV2, plain)
    } catch {
      if !plain.isEmpty {
        plain.resetBytes(in: 0..<plain.count)
      }
      throw error
    }
  }

  /// Phase 2 of transactional `0x01 -> 0x02` upgrade: persists `.sep-v2-committed` in Keychain
  /// (when using real Keychain custody) and locks out future `0x01` reads in memory.
  internal func commitV2Custody() throws {
    lock.lock()
    defer { lock.unlock() }
    try persistV2CommitmentMarkerUnlocked()
  }

  /// Test-only convenience one-shot upgrade combining `beginUpgradeV1ToV2` and `commitV2Custody`.
  /// Production callers MUST use `beginUpgradeV1ToV2` + atomic disk write + `commitV2Custody`
  /// so `.sep-v2-committed` is never persisted ahead of durable storage.
  internal func upgradeEnvelopeIfNeeded(
    _ combined: Data,
    authenticating: Data = Data()
  ) throws -> (data: Data, upgraded: Bool, plaintext: Data) {
    var (data, upgraded, plain) = try beginUpgradeV1ToV2(combined, authenticating: authenticating)
    if upgraded || data.first == Self.formatVersionV2 {
      do {
        try commitV2Custody()
      } catch {
        if !plain.isEmpty {
          plain.resetBytes(in: 0..<plain.count)
        }
        throw error
      }
    }
    return (data, upgraded, plain)
  }

  private func persistV2CommitmentMarkerUnlocked() throws {
    if customEnvelopeProvider == nil && customKeyProvider == nil && v2CommitmentProbe == nil {
      _ = try Self.storeGenericData(
        Self.v2CommittedMarker,
        configuration: configuration,
        accountSuffix: Self.v2CommittedAccountSuffix,
        isSepOrV2: true
      )
    }
    v2CustodyCommitted = true
  }

  private func rejectV1IfV2CommittedUnlocked() throws {
    if configuration.custody == .secureEnclaveRequired || v2CustodyCommitted {
      throw TendrilKeychainError.downgradeRejected
    }
    if try hasCommittedV2MarkerUnlocked() {
      v2CustodyCommitted = true
      throw TendrilKeychainError.downgradeRejected
    }
  }

  private func resolveExistingSepKeyForOpenUnlocked() throws -> any TendrilKeyAgreementPrivateKey {
    if let customEnvelopeProvider {
      return try customEnvelopeProvider()
    }
    guard let blob = try Self.readGenericData(
      configuration: configuration,
      accountSuffix: Self.sepP256AccountSuffix,
      isSepOrV2: true
    ) else {
      throw SecureEnclave.isAvailable
        ? TendrilKeychainError.osStatus(errSecItemNotFound)
        : TendrilKeychainError.secureEnclaveUnavailable
    }
    guard SecureEnclave.isAvailable else {
      throw TendrilKeychainError.secureEnclaveUnavailable
    }
    return SecureEnclaveKeyAgreementAdapter(
      try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
    )
  }

  private static func isMissingEntitlementError(_ error: Error) -> Bool {
    if case TendrilKeychainError.osStatus(let status) = error {
      return status == -34018 || status == errSecMissingEntitlement
    }
    let nsErr = error as NSError
    if nsErr.domain == NSOSStatusErrorDomain {
      let status = OSStatus(nsErr.code)
      return status == -34018 || status == errSecMissingEntitlement
    }
    return false
  }

  private func hasCommittedV2MarkerUnlocked() throws -> Bool {
    do {
      if let v2CommitmentProbe {
        return try v2CommitmentProbe()
      }
      if customEnvelopeProvider != nil || customKeyProvider != nil {
        return false
      }
      return try Self.readGenericData(
        configuration: configuration,
        accountSuffix: Self.v2CommittedAccountSuffix,
        isSepOrV2: true
      ) != nil
    } catch {
      #if os(macOS)
      if configuration.custody != .secureEnclaveRequired
        && configuration.accessGroup == nil
        && Self.isMissingEntitlementError(error)
      {
        return false
      }
      #endif
      throw error
    }
  }

  private func hasExistingSepP256KeyUnlocked() throws -> Bool {
    do {
      return try Self.readGenericData(
        configuration: configuration,
        accountSuffix: Self.sepP256AccountSuffix,
        isSepOrV2: true
      ) != nil
    } catch {
      #if os(macOS)
      if configuration.custody != .secureEnclaveRequired
        && configuration.accessGroup == nil
        && Self.isMissingEntitlementError(error)
      {
        return false
      }
      #endif
      throw error
    }
  }

  private func loadOrCreateSepP256KeyUnlocked() throws -> (key: any TendrilKeyAgreementPrivateKey, createdNew: Bool) {
    if let existingBlob = try Self.readGenericData(
      configuration: configuration,
      accountSuffix: Self.sepP256AccountSuffix,
      isSepOrV2: true
    ) {
      guard SecureEnclave.isAvailable else {
        throw TendrilKeychainError.secureEnclaveUnavailable
      }
      return (
        SecureEnclaveKeyAgreementAdapter(
          try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existingBlob)
        ),
        false
      )
    }
    guard SecureEnclave.isAvailable else {
      throw TendrilKeychainError.secureEnclaveUnavailable
    }
    let accessControl = try Self.makeAccessControl(flags: configuration.accessControlFlags)
    let fresh = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
    if try Self.storeGenericData(
      fresh.dataRepresentation,
      configuration: configuration,
      accountSuffix: Self.sepP256AccountSuffix,
      isSepOrV2: true
    ) {
      return (SecureEnclaveKeyAgreementAdapter(fresh), true)
    }
    if let racedBlob = try Self.readGenericData(
      configuration: configuration,
      accountSuffix: Self.sepP256AccountSuffix,
      isSepOrV2: true
    ) {
      return (
        SecureEnclaveKeyAgreementAdapter(
          try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: racedBlob)
        ),
        false
      )
    }
    throw TendrilKeychainError.osStatus(errSecDuplicateItem)
  }

  internal static func makeAccessControl(flags: SecAccessControlCreateFlags) throws -> SecAccessControl {
    var cfError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      flags,
      &cfError
    ) else {
      if let err = cfError?.takeRetainedValue() {
        throw TendrilKeychainError.osStatus(OSStatus(CFErrorGetCode(err)))
      }
      throw TendrilKeychainError.secureEnclaveUnavailable
    }
    return accessControl
  }

  private static func isFallbackOSStatus(_ status: OSStatus) -> Bool {
    status == -34018
      || status == errSecMissingEntitlement
      || status == errSecNotAvailable
      || status == errSecUnimplemented
  }

  internal static func isFallbackEntitlementOrAvailabilityError(_ error: Error) -> Bool {
    if let kcError = error as? TendrilKeychainError {
      switch kcError {
      case .secureEnclaveUnavailable:
        return true
      case .osStatus(let status):
        return isFallbackOSStatus(status)
      case .invalidData, .downgradeRejected:
        return false
      }
    }
    if let pqError = error as? TendrilMlDsa65Error {
      switch pqError {
      case .secureEnclaveUnavailable:
        return true
      case .keychainStatus(let status):
        return isFallbackOSStatus(status)
      case .invalidPublicKeyLength, .invalidSignatureLength, .signingFailed:
        return false
      }
    }
    let nsErr = error as NSError
    if nsErr.domain == NSOSStatusErrorDomain {
      return isFallbackOSStatus(OSStatus(nsErr.code))
    }
    return false
  }

  internal func keychainQueryBase(accountSuffix: String = "", isSepOrV2: Bool = false) -> [String: Any] {
    Self.keychainQueryBase(
      configuration: configuration,
      accountSuffix: accountSuffix,
      isSepOrV2: isSepOrV2
    )
  }

  internal static func keychainQueryBase(
    configuration: TendrilKeychainConfiguration,
    accountSuffix: String,
    isSepOrV2: Bool
  ) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: configuration.service,
      kSecAttrAccount as String: configuration.account + accountSuffix,
    ]
    if let group = configuration.accessGroup, !group.isEmpty {
      query[kSecAttrAccessGroup as String] = group
    }
    #if os(macOS)
    if isSepOrV2 || configuration.accessGroup != nil || configuration.custody == .secureEnclaveRequired {
      query[kSecUseDataProtectionKeychain as String] = true
    }
    #endif
    return query
  }

  internal static func readGenericData(
    configuration: TendrilKeychainConfiguration,
    accountSuffix: String,
    isSepOrV2: Bool
  ) throws -> Data? {
    try autoreleasepool {
      var query = keychainQueryBase(
        configuration: configuration,
        accountSuffix: accountSuffix,
        isSepOrV2: isSepOrV2
      )
      query[kSecReturnData as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitOne
      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      if status == errSecItemNotFound {
        return nil
      }
      guard status == errSecSuccess else {
        throw TendrilKeychainError.osStatus(status)
      }
      guard let cfItem = item, CFGetTypeID(cfItem) == CFDataGetTypeID() else {
        throw TendrilKeychainError.invalidData
      }
      let cfData = cfItem as! CFData
      let length = CFDataGetLength(cfData)
      guard length > 0, let ptr = CFDataGetBytePtr(cfData) else {
        throw TendrilKeychainError.invalidData
      }
      return Data(bytes: ptr, count: length)
    }
  }

  internal static func storeGenericData(
    _ data: Data,
    configuration: TendrilKeychainConfiguration,
    accountSuffix: String,
    isSepOrV2: Bool
  ) throws -> Bool {
    try autoreleasepool {
      try data.withUnsafeBytes { rawBytes in
        guard rawBytes.count > 0, let base = rawBytes.baseAddress else {
          throw TendrilKeychainError.invalidData
        }
        guard let cfData = CFDataCreate(
          kCFAllocatorDefault,
          base.assumingMemoryBound(to: UInt8.self),
          rawBytes.count
        ) else {
          throw TendrilKeychainError.invalidData
        }
        var query = keychainQueryBase(
          configuration: configuration,
          accountSuffix: accountSuffix,
          isSepOrV2: isSepOrV2
        )
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = cfData
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
          return false
        }
        guard status == errSecSuccess else {
          throw TendrilKeychainError.osStatus(status)
        }
        return true
      }
    }
  }

  internal static func deleteGenericItem(
    configuration: TendrilKeychainConfiguration,
    accountSuffix: String,
    isSepOrV2: Bool
  ) throws {
    try autoreleasepool {
      let query = keychainQueryBase(
        configuration: configuration,
        accountSuffix: accountSuffix,
        isSepOrV2: isSepOrV2
      )
      let status = SecItemDelete(query as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw TendrilKeychainError.osStatus(status)
      }
    }
  }

  private static func zeroize(_ buffer: UnsafeMutableRawBufferPointer) {
    guard let base = buffer.baseAddress, buffer.count > 0 else { return }
    #if canImport(Darwin)
    _ = memset_s(base, buffer.count, 0, buffer.count)
    #else
    let bytes = base.assumingMemoryBound(to: UInt8.self)
    for i in 0..<buffer.count {
      bytes[i] = 0
    }
    #endif
  }

  private func readKey() throws -> SymmetricKey? {
    try autoreleasepool {
      var query = keychainQueryBase(accountSuffix: "", isSepOrV2: false)
      query[kSecReturnData as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitOne
      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      if status == errSecItemNotFound {
        return nil
      }
      guard status == errSecSuccess else {
        throw TendrilKeychainError.osStatus(status)
      }
      // Note: CFData returned by SecItemCopyMatching is owned and freed by CoreFoundation
      // when the enclosing autoreleasepool drains.
      guard let cfItem = item, CFGetTypeID(cfItem) == CFDataGetTypeID() else {
        throw TendrilKeychainError.invalidData
      }
      let cfData = cfItem as! CFData
      let length = CFDataGetLength(cfData)
      guard length == 32, let ptr = CFDataGetBytePtr(cfData) else {
        throw TendrilKeychainError.invalidData
      }
      let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: 32, alignment: 1)
      defer {
        Self.zeroize(scratch)
        scratch.deallocate()
      }
      scratch.baseAddress?.copyMemory(from: ptr, byteCount: 32)
      return SymmetricKey(data: scratch)
    }
  }

  private func storeKey(_ key: SymmetricKey) throws -> Bool {
    try autoreleasepool {
      try key.withUnsafeBytes { rawBytes in
        guard rawBytes.count == 32, let base = rawBytes.baseAddress else {
          throw TendrilKeychainError.invalidData
        }
        // Note: CFData passed to SecItemAdd is owned and freed by CoreFoundation
        // inside this autoreleasepool; rawBytes itself is backed by CryptoKit SecureBytes.
        guard let cfData = CFDataCreate(
          kCFAllocatorDefault,
          base.assumingMemoryBound(to: UInt8.self),
          32
        ) else {
          throw TendrilKeychainError.invalidData
        }
        var query = keychainQueryBase(accountSuffix: "", isSepOrV2: false)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = cfData
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
          return false
        }
        guard status == errSecSuccess else {
          throw TendrilKeychainError.osStatus(status)
        }
        return true
      }
    }
  }
}
#endif

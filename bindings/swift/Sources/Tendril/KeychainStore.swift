import Foundation

#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security

public enum TendrilKeychainError: Error {
  case osStatus(OSStatus)
  case invalidData
}

public final class TendrilKeychainStore {
  private static let formatVersion: UInt8 = 1
  private static let domainAad = Data("tendril.state.v1\0".utf8)

  private let lock = NSLock()
  private let service: String
  private let account: String
  private let customKeyProvider: (@Sendable () throws -> SymmetricKey)?

  public convenience init(service: String = "dev.tendril.state", account: String = "master-key-v1") {
    self.init(service: service, account: account, customKeyProvider: nil)
  }

  internal init(
    service: String = "dev.tendril.state",
    account: String = "master-key-v1",
    customKeyProvider: (@Sendable () throws -> SymmetricKey)?
  ) {
    self.service = service
    self.account = account
    self.customKeyProvider = customKeyProvider
  }

  public func loadOrCreateMasterKey() throws -> SymmetricKey {
    if let customKeyProvider {
      return try customKeyProvider()
    }
    lock.lock()
    defer { lock.unlock() }
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

  private func combinedAad(_ authenticating: Data) -> Data {
    var aad = Self.domainAad
    if !authenticating.isEmpty {
      aad.append(authenticating)
    }
    return aad
  }

  public func sealState(_ plaintext: Data, authenticating: Data = Data()) throws -> Data {
    let key = try loadOrCreateMasterKey()
    let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: combinedAad(authenticating))
    guard let combined = sealed.combined else {
      throw TendrilKeychainError.invalidData
    }
    var out = Data(capacity: 1 + combined.count)
    out.append(Self.formatVersion)
    out.append(combined)
    return out
  }

  public func openState(_ combined: Data, authenticating: Data = Data()) throws -> Data {
    guard combined.count > 1, combined[combined.startIndex] == Self.formatVersion else {
      throw TendrilKeychainError.invalidData
    }
    let key = try loadOrCreateMasterKey()
    let box = try AES.GCM.SealedBox(combined: combined.dropFirst())
    return try AES.GCM.open(box, using: key, authenticating: combinedAad(authenticating))
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
      let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
      ]
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
        let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrService as String: service,
          kSecAttrAccount as String: account,
          kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
          kSecValueData as String: cfData,
        ]
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

import Foundation

#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security

public enum TendrilKeychainError: Error {
  case osStatus(OSStatus)
  case invalidData
}

public final class TendrilKeychainStore {
  private let lock = NSLock()
  private let service: String
  private let account: String

  public init(service: String = "dev.tendril.state", account: String = "master-key-v1") {
    self.service = service
    self.account = account
  }

  public func loadOrCreateMasterKey() throws -> SymmetricKey {
    lock.lock()
    defer { lock.unlock() }
    if let existing = try readKeyData() {
      guard existing.count == 32 else {
        throw TendrilKeychainError.invalidData
      }
      return SymmetricKey(data: existing)
    }
    let fresh = SymmetricKey(size: .bits256)
    let raw = fresh.withUnsafeBytes { Data($0) }
    try storeKeyData(raw)
    return fresh
  }

  public func sealState(_ plaintext: Data, authenticating: Data = Data()) throws -> Data {
    let key = try loadOrCreateMasterKey()
    let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: authenticating)
    guard let combined = sealed.combined else {
      throw TendrilKeychainError.invalidData
    }
    return combined
  }

  public func openState(_ combined: Data, authenticating: Data = Data()) throws -> Data {
    let key = try loadOrCreateMasterKey()
    let box = try AES.GCM.SealedBox(combined: combined)
    return try AES.GCM.open(box, using: key, authenticating: authenticating)
  }

  private func readKeyData() throws -> Data? {
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
    guard status == errSecSuccess, let data = item as? Data else {
      throw TendrilKeychainError.osStatus(status)
    }
    return data
  }

  private func storeKeyData(_ data: Data) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: data,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw TendrilKeychainError.osStatus(status)
    }
  }
}
#endif

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

  public init(service: String = "dev.tendril.state", account: String = "master-key-v1") {
    self.service = service
    self.account = account
  }

  public func loadOrCreateMasterKey() throws -> SymmetricKey {
    lock.lock()
    defer { lock.unlock() }
    if var existing = try readKeyData() {
      defer { existing.resetBytes(in: 0..<existing.count) }
      guard existing.count == 32 else {
        throw TendrilKeychainError.invalidData
      }
      return SymmetricKey(data: existing)
    }
    let fresh = SymmetricKey(size: .bits256)
    var raw = fresh.withUnsafeBytes { Data($0) }
    defer { raw.resetBytes(in: 0..<raw.count) }
    if try storeKeyData(raw) {
      return fresh
    }
    if var raced = try readKeyData() {
      defer { raced.resetBytes(in: 0..<raced.count) }
      guard raced.count == 32 else {
        throw TendrilKeychainError.invalidData
      }
      return SymmetricKey(data: raced)
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

  private func storeKeyData(_ data: Data) throws -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: data,
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
#endif

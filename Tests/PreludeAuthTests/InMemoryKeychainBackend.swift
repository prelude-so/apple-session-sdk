import Foundation
@testable import PreludeAuth
import Security

/// In-memory, thread-safe `KeychainBackend` for tests. Vanilla SPM
/// iOS test bundles have no app host, so the real Keychain refuses
/// access with `errSecMissingEntitlement`.
///
/// Models only what the SDK uses:
/// - `copyMatching` by `kSecAttrApplicationTag` (keys) or
///   `(kSecAttrService, kSecAttrAccount)` (passwords)
/// - `SecItemAdd` → `errSecDuplicateItem` on collisions
/// - `SecItemUpdate` → `errSecItemNotFound` on misses
/// - `SecKeyCreateRandomKey` with `isPermanent: true` registers
///   against the internal store
///
/// Per-call atomic only; compositions (copyMatching + add) are
/// deliberately non-atomic so tests exercise the production locks'
/// race window.
final class InMemoryKeychainBackend: KeychainBackend, @unchecked Sendable {
    private static let classKey = kSecClassKey as String
    private static let classGenericPassword = kSecClassGenericPassword as String

    private struct Item {
        let value: AnyObject
    }

    private var keys: [Data: Item] = [:]
    private var passwords: [PasswordKey: Item] = [:]

    private struct PasswordKey: Hashable {
        let service: String
        let account: String
    }

    private let lock = NSLock()

    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef? {
        lock.lock()
        defer { lock.unlock() }

        guard let secClass = query[kSecClass as String] as? String else { return nil }

        switch secClass {
        case Self.classKey:
            guard let tag = query[kSecAttrApplicationTag as String] as? Data,
                  let item = keys[tag] else {
                return nil
            }
            return item.value as CFTypeRef

        case Self.classGenericPassword:
            guard
                let service = query[kSecAttrService as String] as? String,
                let account = query[kSecAttrAccount as String] as? String,
                let item = passwords[PasswordKey(service: service, account: account)]
            else {
                return nil
            }
            return item.value as CFTypeRef

        default:
            return nil
        }
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }

        guard let secClass = attributes[kSecClass as String] as? String else {
            return errSecParam
        }

        switch secClass {
        case Self.classGenericPassword:
            guard
                let service = attributes[kSecAttrService as String] as? String,
                let account = attributes[kSecAttrAccount as String] as? String,
                let data = attributes[kSecValueData as String] as? Data
            else {
                return errSecParam
            }
            let passwordKey = PasswordKey(service: service, account: account)
            if passwords[passwordKey] != nil {
                return errSecDuplicateItem
            }
            passwords[passwordKey] = Item(value: data as NSData)
            return errSecSuccess

        default:
            return errSecUnimplemented
        }
    }

    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }

        guard
            let secClass = query[kSecClass as String] as? String,
            secClass == Self.classGenericPassword,
            let service = query[kSecAttrService as String] as? String,
            let account = query[kSecAttrAccount as String] as? String,
            let newData = attributesToUpdate[kSecValueData as String] as? Data
        else {
            return errSecParam
        }

        let passwordKey = PasswordKey(service: service, account: account)
        guard passwords[passwordKey] != nil else {
            return errSecItemNotFound
        }
        passwords[passwordKey] = Item(value: newData as NSData)
        return errSecSuccess
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }

        guard let secClass = query[kSecClass as String] as? String else {
            return errSecParam
        }

        switch secClass {
        case Self.classKey:
            guard let tag = query[kSecAttrApplicationTag as String] as? Data else {
                return errSecParam
            }
            return keys.removeValue(forKey: tag) == nil ? errSecItemNotFound : errSecSuccess

        case Self.classGenericPassword:
            guard
                let service = query[kSecAttrService as String] as? String,
                let account = query[kSecAttrAccount as String] as? String
            else {
                return errSecParam
            }
            let passwordKey = PasswordKey(service: service, account: account)
            return passwords.removeValue(forKey: passwordKey) == nil ? errSecItemNotFound : errSecSuccess

        default:
            return errSecUnimplemented
        }
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        // Generate an ephemeral EC keypair via the real Security
        // API and register it under the provided tag. Strip the
        // attrs that would push iOS to persist to the real Keychain.
        var ephemeralAttrs = attributes
        if var privateAttrs = ephemeralAttrs[kSecPrivateKeyAttrs as String] as? [String: Any] {
            privateAttrs[kSecAttrIsPermanent as String] = false
            privateAttrs.removeValue(forKey: kSecAttrAccessControl as String)
            ephemeralAttrs[kSecPrivateKeyAttrs as String] = privateAttrs
        }
        ephemeralAttrs.removeValue(forKey: kSecAttrTokenID as String)

        var genError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(ephemeralAttrs as CFDictionary, &genError) else {
            throw DPoPKeyStoreError.keyGenerationFailed(
                underlying: genError?.takeRetainedValue()
            )
        }

        if let privateAttrs = attributes[kSecPrivateKeyAttrs as String] as? [String: Any],
           let isPermanent = privateAttrs[kSecAttrIsPermanent as String] as? Bool,
           isPermanent,
           let tag = privateAttrs[kSecAttrApplicationTag as String] as? Data {
            lock.lock()
            defer { lock.unlock() }
            if keys[tag] != nil {
                throw DPoPKeyStoreError.keychainFailure(errSecDuplicateItem)
            }
            keys[tag] = Item(value: key)
        }

        return key
    }
}

import Foundation
import Security

/// Minimal abstraction over the `SecItem` / `SecKey` surface the
/// SDK uses. Tests inject an in-memory backend because unhosted SPM
/// iOS test bundles can't reach the real Keychain
/// (`errSecMissingEntitlement`).
protocol KeychainBackend: Sendable {
    /// `SecItemCopyMatching`. Returns `nil` on `errSecItemNotFound`.
    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef?

    /// `SecItemAdd`. Returns raw `OSStatus` so callers can branch
    /// on `errSecDuplicateItem`.
    func add(_ attributes: [String: Any]) -> OSStatus

    /// `SecItemUpdate`. Returns raw `OSStatus` so callers can
    /// branch on `errSecItemNotFound`.
    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus

    /// `SecItemDelete`. Callers typically treat `errSecItemNotFound`
    /// as a no-op.
    func delete(_ query: [String: Any]) -> OSStatus

    /// `SecKeyCreateRandomKey`. With `kSecAttrIsPermanent: true` and
    /// a `kSecAttrApplicationTag`, the key must be retrievable via
    /// a matching ``copyMatching``.
    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey
}

struct DefaultKeychainBackend: KeychainBackend {
    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw DPoPKeyStoreError.keychainFailure(status)
        }
        return item
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }

    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        var genError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
            throw DPoPKeyStoreError.keyGenerationFailed(
                underlying: genError?.takeRetainedValue()
            )
        }
        return key
    }
}

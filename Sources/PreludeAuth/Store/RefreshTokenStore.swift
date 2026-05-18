import Foundation
import Security

struct RefreshTokenRecord: Codable, Equatable {
    var refreshToken: String
    /// ISO 8601 expiry as returned by the backend; stored verbatim.
    var refreshTokenExpiresAt: String?
}

/// Defense in depth: every textual representation drops the bearer
/// refresh token. The expiry stays — debuggable and not sensitive.
extension RefreshTokenRecord: CustomStringConvertible {
    var description: String {
        "RefreshTokenRecord(refreshToken: <redacted>, refreshTokenExpiresAt: \(refreshTokenExpiresAt ?? "nil"))"
    }
}

extension RefreshTokenRecord: CustomDebugStringConvertible {
    var debugDescription: String {
        description
    }
}

extension RefreshTokenRecord: CustomReflectable {
    var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "refreshToken": "<redacted>",
                "refreshTokenExpiresAt": refreshTokenExpiresAt as Any,
            ],
            displayStyle: .struct
        )
    }
}

/// Keychain-backed storage for refresh tokens, scoped by Prelude
/// domain. One generic-password item per domain; the password
/// payload is a JSON-encoded ``RefreshTokenRecord``. Accessibility
/// is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — usable
/// after first unlock, never backed up across devices.
struct RefreshTokenStore {
    private static let service = "so.prelude.auth.refresh"

    private let keychain: KeychainBackend

    init(keychain: KeychainBackend = DefaultKeychainBackend()) {
        self.keychain = keychain
    }

    /// Stored record for `domain`, or `nil` if none or the blob is
    /// unreadable (older-schema written by a prior SDK — recoverable
    /// via a fresh login).
    func get(domain: String) throws -> RefreshTokenRecord? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        let item: CFTypeRef?
        do {
            item = try keychain.copyMatching(query)
        } catch {
            throw Self.toSessionError(error)
        }
        guard let item else { return nil }
        guard let data = item as? Data else {
            throw SessionTokenStoreError.keychainFailure(errSecDecode)
        }
        return try? JSONDecoder().decode(RefreshTokenRecord.self, from: data)
    }

    func set(domain: String, record: RefreshTokenRecord) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(record)
        } catch {
            throw SessionTokenStoreError.codecFailure
        }

        let matchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
        ]
        let update: [String: Any] = [kSecValueData as String: data]

        let updateStatus = keychain.update(matchQuery, attributesToUpdate: update)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw SessionTokenStoreError.keychainFailure(updateStatus)
        }

        var addAttrs = matchQuery
        addAttrs[kSecValueData as String] = data
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = keychain.add(addAttrs)
        guard addStatus == errSecSuccess else {
            throw SessionTokenStoreError.keychainFailure(addStatus)
        }
    }

    func delete(domain: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
        ]
        let status = keychain.delete(query)
        if status != errSecSuccess, status != errSecItemNotFound {
            throw SessionTokenStoreError.keychainFailure(status)
        }
    }

    private static func toSessionError(_ error: Error) -> SessionTokenStoreError {
        if let keyStoreError = error as? DPoPKeyStoreError,
           case let .keychainFailure(status) = keyStoreError {
            return .keychainFailure(status)
        }
        return .keychainFailure(errSecDecode)
    }
}

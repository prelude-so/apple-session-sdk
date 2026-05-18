import Foundation
@testable import PreludeAuth
import Security
import XCTest

/// Storage attributes for the refresh token. The bearer survives
/// app restart but never escapes the device — pin both halves.
final class RefreshTokenStoreTests: XCTestCase {
    /// First write to a fresh domain must `Add` with
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
    func test_set_addsWithAfterFirstUnlockThisDeviceOnly() throws {
        let recorder = RecordingKeychainBackend(inner: InMemoryKeychainBackend())
        let store = RefreshTokenStore(keychain: recorder)

        try store.set(
            domain: "example.com",
            record: RefreshTokenRecord(refreshToken: "r1", refreshTokenExpiresAt: nil)
        )

        let add = try XCTUnwrap(recorder.adds.first)
        XCTAssertEqual(
            add[kSecAttrAccessible as String] as? String,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        )
    }

    /// Round-trip across a "cold start" (rebuild the store against
    /// the same backend) to pin that the value lives in the
    /// Keychain backend, not in process memory.
    func test_record_roundTripsAcrossFreshStoreInstance() throws {
        let backend = InMemoryKeychainBackend()
        let writer = RefreshTokenStore(keychain: backend)
        try writer.set(
            domain: "example.com",
            record: RefreshTokenRecord(refreshToken: "r1", refreshTokenExpiresAt: "2030-01-01")
        )

        let reader = RefreshTokenStore(keychain: backend)
        XCTAssertEqual(
            try reader.get(domain: "example.com"),
            RefreshTokenRecord(refreshToken: "r1", refreshTokenExpiresAt: "2030-01-01")
        )
    }
}

// MARK: - Recording backend

/// Wraps a `KeychainBackend` and records every `add` so a test can
/// inspect the attributes the production store passed in. All
/// other ops delegate verbatim.
private final class RecordingKeychainBackend: KeychainBackend, @unchecked Sendable {
    let inner: KeychainBackend
    private(set) var adds: [[String: Any]] = []
    private let lock = NSLock()

    init(inner: KeychainBackend) {
        self.inner = inner
    }

    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef? {
        try inner.copyMatching(query)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        lock.lock(); adds.append(attributes); lock.unlock()
        return inner.add(attributes)
    }

    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus {
        inner.update(query, attributesToUpdate: attributesToUpdate)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        inner.delete(query)
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        try inner.createRandomKey(attributes)
    }
}

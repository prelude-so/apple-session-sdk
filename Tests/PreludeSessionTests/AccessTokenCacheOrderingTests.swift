import Security
import XCTest
@testable import PreludeSession

/// Keychain-before-memory ordering invariant in ``AccessTokenCache``:
/// ``set``, ``invalidate``, and ``clear`` must perform their Keychain
/// operation before mutating the in-memory dictionary, so a failed
/// Keychain write doesn't leave memory and disk in disagreement.
///
/// The cache is an actor; every call site here `await`s it.
final class AccessTokenCacheOrderingTests: XCTestCase {
    // MARK: - Fixtures

    private static let fixedEpoch = 1_700_000_000

    private let domain = "app.example.com"

    private let clock: NowProvider = {
        Date(timeIntervalSince1970: TimeInterval(AccessTokenCacheOrderingTests.fixedEpoch))
    }

    private func makeEntry(
        accessToken: String = "jwt-token",
        expiresIn: Int = 300
    ) -> AccessTokenEntry {
        AccessTokenEntry(
            accessToken: accessToken,
            expiresAt: Self.fixedEpoch + expiresIn
        )
    }

    // MARK: - Happy-path

    func testSetThenGetRoundTripsThroughBackend() async throws {
        let backend = InMemoryKeychainBackend()
        let cache = AccessTokenCache(clock: clock, keychain: backend)
        let entry = makeEntry()

        try await cache.set(domain: domain, entry: entry)

        let got = await cache.get(domain: domain)
        XCTAssertEqual(got, entry)
    }

    func testHydrateReadsWhatSetWrote() async throws {
        let backend = InMemoryKeychainBackend()
        let writer = AccessTokenCache(clock: clock, keychain: backend)
        let entry = makeEntry()
        try await writer.set(domain: domain, entry: entry)

        let reader = AccessTokenCache(clock: clock, keychain: backend)
        await reader.hydrate(domain: domain)

        let got = await reader.get(domain: domain)
        XCTAssertEqual(got, entry)
    }

    func testClearRemovesFromBothStores() async throws {
        let backend = InMemoryKeychainBackend()
        let cache = AccessTokenCache(clock: clock, keychain: backend)
        try await cache.set(domain: domain, entry: makeEntry())

        try await cache.clear(domain: domain)

        let inMemory = await cache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(inMemory)

        let reader = AccessTokenCache(clock: clock, keychain: backend)
        await reader.hydrate(domain: domain)
        let onDisk = await reader.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(onDisk)
    }

    // MARK: - Ordering invariants

    func testFailedSetLeavesMemoryUntouched() async throws {
        let backend = FailingKeychainBackend(inner: InMemoryKeychainBackend())
        let cache = AccessTokenCache(clock: clock, keychain: backend)
        backend.updateStatusOverride = errSecInteractionNotAllowed
        backend.addStatusOverride = errSecInteractionNotAllowed

        await assertThrowsKeychainFailure(status: errSecInteractionNotAllowed) {
            try await cache.set(domain: self.domain, entry: self.makeEntry())
        }

        let inMemory = await cache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(inMemory, "memory must not hold the new entry when the Keychain write failed")
    }

    func testFailedInvalidateKeepsOriginalEntryInMemory() async throws {
        let backend = FailingKeychainBackend(inner: InMemoryKeychainBackend())
        let cache = AccessTokenCache(clock: clock, keychain: backend)

        let original = makeEntry(expiresIn: 300)
        try await cache.set(domain: domain, entry: original)

        backend.updateStatusOverride = errSecInteractionNotAllowed
        backend.addStatusOverride = errSecInteractionNotAllowed

        await assertThrowsKeychainFailure(status: errSecInteractionNotAllowed) {
            try await cache.invalidate(domain: self.domain)
        }

        let visible = await cache.get(domain: domain)
        XCTAssertEqual(visible, original)
        let raw = await cache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(raw?.expiresAt, original.expiresAt)
    }

    func testFailedInvalidateDoesNotDivergeFromKeychainAcrossColdStart() async throws {
        let backend = FailingKeychainBackend(inner: InMemoryKeychainBackend())
        let cache = AccessTokenCache(clock: clock, keychain: backend)

        let original = makeEntry(expiresIn: 300)
        try await cache.set(domain: domain, entry: original)

        backend.updateStatusOverride = errSecInteractionNotAllowed
        backend.addStatusOverride = errSecInteractionNotAllowed
        await assertThrowsKeychainFailure(status: errSecInteractionNotAllowed) {
            try await cache.invalidate(domain: self.domain)
        }

        // Cold start: fresh cache, same backend. `hydrate` uses
        // `copyMatching`, which is not in the fail set.
        let fresh = AccessTokenCache(clock: clock, keychain: backend)
        await fresh.hydrate(domain: domain)

        let warm = await cache.get(domain: domain)
        XCTAssertEqual(warm, original)
        let cold = await fresh.get(domain: domain)
        XCTAssertEqual(cold, original)
    }

    func testFailedClearLeavesEntryObservable() async throws {
        let backend = FailingKeychainBackend(inner: InMemoryKeychainBackend())
        let cache = AccessTokenCache(clock: clock, keychain: backend)
        let entry = makeEntry()
        try await cache.set(domain: domain, entry: entry)

        backend.deleteStatusOverride = errSecInteractionNotAllowed

        await assertThrowsKeychainFailure(status: errSecInteractionNotAllowed) {
            try await cache.clear(domain: self.domain)
        }

        // Memory still shows the entry so the caller can see that
        // clear didn't stick and retry / surface the error.
        let visible = await cache.get(domain: domain)
        XCTAssertEqual(visible, entry)
    }

    // MARK: - Helpers

    /// Async equivalent of `XCTAssertThrowsError` that pattern-matches
    /// against ``SessionTokenStoreError/keychainFailure`` with the
    /// expected `OSStatus`. Failing the throw or matching either
    /// status yields a single `XCTFail` at the call site.
    private func assertThrowsKeychainFailure(
        status expected: OSStatus,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("expected throw, got success", file: file, line: line)
        } catch let SessionTokenStoreError.keychainFailure(status) {
            XCTAssertEqual(status, expected, file: file, line: line)
        } catch {
            XCTFail("expected SessionTokenStoreError.keychainFailure, got \(error)", file: file, line: line)
        }
    }
}

// MARK: - Test double

/// Forwards every call to an inner backend but can be told to
/// return a specific `OSStatus` for ``add``/``update``/``delete``
/// or throw from ``copyMatching``. Overrides are sticky — set
/// once and they apply to every subsequent call until cleared.
///
/// Not concurrency-safe; the accompanying tests drive it
/// sequentially.
final class FailingKeychainBackend: KeychainBackend, @unchecked Sendable {
    private let inner: KeychainBackend
    var addStatusOverride: OSStatus?
    var updateStatusOverride: OSStatus?
    var deleteStatusOverride: OSStatus?
    var copyMatchingError: DPoPKeyStoreError?

    init(inner: KeychainBackend) {
        self.inner = inner
    }

    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef? {
        if let error = copyMatchingError {
            throw error
        }
        return try inner.copyMatching(query)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        if let override = addStatusOverride {
            return override
        }
        return inner.add(attributes)
    }

    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus {
        if let override = updateStatusOverride {
            return override
        }
        return inner.update(query, attributesToUpdate: attributesToUpdate)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        if let override = deleteStatusOverride {
            return override
        }
        return inner.delete(query)
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        try inner.createRandomKey(attributes)
    }
}

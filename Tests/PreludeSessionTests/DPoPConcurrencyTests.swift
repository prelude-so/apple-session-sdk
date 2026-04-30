import XCTest
@testable import PreludeSession

/// Concurrency invariants for ``DPoPKeyStore/getOrCreate(domain:)``
/// and the lock in ``DPoPNonceStore/set(domain:nonce:)``. Keychain
/// ops are individually atomic but their compositions
/// (`get → nil? → create`; `update → notFound → add`) are not, so
/// the per-instance locks have to serialise them.
///
/// Both stores own their own locks: production wires up a single
/// ``DPoPKeyStore`` per ``PreludeSessionClient``, so in-process
/// callers naturally share that one lock. Multi-instance and
/// cross-process callers fall back on the duplicate-item retry
/// inside ``DPoPKeyStore/readOrCreateUnderLock(_:domain:)`` and
/// the duplicate-item fallback in ``DPoPNonceStore/set``.
///
/// ``InMemoryKeychainBackend`` preserves the same per-call
/// atomicity + race window as the real OS.
final class DPoPConcurrencyTests: XCTestCase {
    private var domain: String!
    private var backend: InMemoryKeychainBackend!

    override func setUp() {
        super.setUp()
        domain = "race-test-\(UUID().uuidString)"
        backend = InMemoryKeychainBackend()
    }

    override func tearDown() {
        domain = nil
        backend = nil
        super.tearDown()
    }

    // MARK: - Key-store race (single instance)

    /// N concurrent `getOrCreate` callers on a fresh domain must
    /// observe one and only one public key.
    func test_getOrCreate_concurrentCallersShareOneKey() async throws {
        let store = SoftwareDPoPKeyStore(backend: backend)
        let concurrentCallers = 64

        var publicKeyFingerprints: [String] = []
        try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<concurrentCallers {
                let domain = self.domain!
                group.addTask {
                    let key = try store.getOrCreate(domain: domain)
                    return try Self.publicKeyFingerprint(key)
                }
            }
            for try await fingerprint in group {
                publicKeyFingerprints.append(fingerprint)
            }
        }

        XCTAssertEqual(publicKeyFingerprints.count, concurrentCallers)
        let uniqueKeys = Set(publicKeyFingerprints)
        XCTAssertEqual(
            uniqueKeys.count,
            1,
            "Expected one shared key, got \(uniqueKeys.count). Per-instance creationLock regressed."
        )
    }

    // MARK: - Key-store race (multi instance / multi process)

    /// Two independent stores sharing only the Keychain backend
    /// (no shared lock) must still converge on one key for
    /// concurrent first-time callers. Models the production race
    /// for two ``PreludeSessionClient`` instances in the same
    /// process — or any second process — targeting the same
    /// domain. The race window is the gap between an empty
    /// `get(domain:)` and `create(domain:)`: once one store
    /// commits a key, the other's `create` fails with
    /// `errSecDuplicateItem` and
    /// ``DPoPKeyStore/readOrCreateUnderLock(_:domain:)`` re-reads
    /// to share the racing winner's key.
    func test_getOrCreate_independentInstancesShareOneKeyViaBackend() async throws {
        let storeA = SoftwareDPoPKeyStore(backend: backend)
        let storeB = SoftwareDPoPKeyStore(backend: backend)
        let concurrentCallers = 64

        var publicKeyFingerprints: [String] = []
        try await withThrowingTaskGroup(of: String.self) { group in
            for i in 0..<concurrentCallers {
                let domain = self.domain!
                let store = i.isMultiple(of: 2) ? storeA : storeB
                group.addTask {
                    let key = try store.getOrCreate(domain: domain)
                    return try Self.publicKeyFingerprint(key)
                }
            }
            for try await fingerprint in group {
                publicKeyFingerprints.append(fingerprint)
            }
        }

        XCTAssertEqual(publicKeyFingerprints.count, concurrentCallers)
        let uniqueKeys = Set(publicKeyFingerprints)
        XCTAssertEqual(
            uniqueKeys.count,
            1,
            "Independent stores on a shared backend must converge on one key via the duplicate-item fallback. Got \(uniqueKeys.count)."
        )
    }

    /// Direct check on the duplicate-item fallback: store A
    /// creates the key first, then store B — running its own
    /// `getOrCreate` after A's commit landed in the backend —
    /// must return A's key without throwing. This is the
    /// fallback's deterministic path; the multi-instance fan-out
    /// test above covers the racy path.
    func test_getOrCreate_secondInstanceReusesFirstInstancesKey() throws {
        let storeA = SoftwareDPoPKeyStore(backend: backend)
        let storeB = SoftwareDPoPKeyStore(backend: backend)

        let keyA = try storeA.getOrCreate(domain: domain)
        let keyB = try storeB.getOrCreate(domain: domain)

        XCTAssertEqual(
            try Self.publicKeyFingerprint(keyA),
            try Self.publicKeyFingerprint(keyB),
            "A second store must reuse the existing key, not mint a new one."
        )
    }

    // MARK: - Nonce-store race

    /// N concurrent first-time `set` calls must all succeed.
    /// Without the lock + `errSecDuplicateItem` fallback, several
    /// callers race to `SecItemAdd` and losers throw.
    func test_setNonce_concurrentFirstTimeWritesAllSucceed() async throws {
        let nonceStore = DPoPNonceStore(backend: backend)
        let concurrentCallers = 64

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<concurrentCallers {
                let domain = self.domain!
                group.addTask {
                    try nonceStore.set(domain: domain, nonce: "nonce-\(i)")
                }
            }
            for try await _ in group { }
        }

        let stored = try nonceStore.get(domain: domain)
        XCTAssertNotNil(stored)
        XCTAssertTrue(stored?.hasPrefix("nonce-") ?? false)
    }

    /// Two independent nonce stores sharing the backend (no shared
    /// lock) racing to first-write must both succeed: the loser's
    /// `add` returns `errSecDuplicateItem` and falls through to
    /// the overwrite path. Mirrors the multi-client `getOrCreate`
    /// case for the nonce side.
    func test_setNonce_independentInstancesAllSucceed() async throws {
        let storeA = DPoPNonceStore(backend: backend)
        let storeB = DPoPNonceStore(backend: backend)
        let concurrentCallers = 64

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<concurrentCallers {
                let domain = self.domain!
                let store = i.isMultiple(of: 2) ? storeA : storeB
                group.addTask {
                    try store.set(domain: domain, nonce: "nonce-\(i)")
                }
            }
            for try await _ in group { }
        }

        let stored = try storeA.get(domain: domain)
        XCTAssertNotNil(stored)
        XCTAssertTrue(stored?.hasPrefix("nonce-") ?? false)
    }

    // MARK: - Helpers

    /// Deterministic fingerprint for a DPoP key.
    private static func publicKeyFingerprint(_ key: DPoPKey) throws -> String {
        let jwk = try key.exportPublicJWK()
        return "\(jwk["x"] ?? "").\(jwk["y"] ?? "")"
    }
}

import Foundation
@testable import PreludeAuth
import Security
import XCTest

/// Concurrency and robustness invariants of
/// ``PreludeAuthClient/logout()``.
final class LogoutTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        // The client derives its domain from `baseURL.host`. A UUID
        // in the host keeps parallel test shards isolated.
        domain = "logout-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil
        baseURL = nil
        clock = nil
        super.tearDown()
    }

    /// N concurrent logouts must coalesce into one `/revoke`.
    func test_concurrentLogouts_hitRevokeOnce() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 16 {
                group.addTask { try await fixture.client.logout() }
            }
            for try await _ in group {}
        }

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/revoke"), 1)
        try await fixture.assertWiped()
    }

    /// `/revoke` must carry the post-rotation refresh token, not
    /// the pre-rotation one.
    func test_logoutDrainsInflightRefresh() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)
        fixture.http.installGate(path: "/v1/session/refresh")

        let refresh = Task { try await fixture.client.refresh() }
        try await waitUntil { fixture.http.requestCount(forPath: "/v1/session/refresh") >= 1 }

        let logout = Task { try await fixture.client.logout() }
        fixture.http.releaseGate(path: "/v1/session/refresh")

        _ = try await refresh.value
        try await logout.value

        let revoked = fixture.http.requests(forPath: "/v1/session/revoke")
        XCTAssertEqual(revoked.count, 1)
        XCTAssertEqual(
            revoked.first?.value(forHTTPHeaderField: HTTPHeader.refreshToken),
            "refresh-v2",
            "logout signed /revoke with the pre-rotation refresh token"
        )
    }

    /// A failing Keychain delete must not short-circuit the other
    /// deletes or prevent `/revoke` from firing. The captured wipe
    /// error is rethrown after the server attempt.
    func test_clearAllStores_partialFailure() async throws {
        let failing = FailingDeleteBackend(
            underlying: InMemoryKeychainBackend(),
            failDeleteForService: "so.prelude.auth.refresh"
        )
        let fixture = try Fixture.make(
            domain: domain,
            baseURL: baseURL,
            clock: clock,
            backend: failing
        )
        try await fixture.prePopulate(nonce: "nonce-abc")
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        do {
            try await fixture.client.logout()
            XCTFail("expected logout to re-throw the partial-wipe failure")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/revoke"), 1)
        XCTAssertNil(try fixture.keyStore.get(domain: domain))
        XCTAssertNil(try fixture.keyStore.getNonce(domain: domain))
        let cached1 = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(cached1)
        // Refresh token remains — that's the delete we broke.
        XCTAssertNotNil(try fixture.refreshTokenStore.get(domain: domain))
    }

    /// When both the wipe and `/revoke` fail, ``logout()`` surfaces
    /// the wipe error: a stale credential left on the device is
    /// more security-critical than a server session that TTLs out
    /// on its own, and the caller needs the wipe error to know a
    /// retry is required.
    func test_partialWipe_andRevokeFailure_surfacesWipeError() async throws {
        let failing = FailingDeleteBackend(
            underlying: InMemoryKeychainBackend(),
            failDeleteForService: "so.prelude.auth.refresh"
        )
        let fixture = try Fixture.make(
            domain: domain,
            baseURL: baseURL,
            clock: clock,
            backend: failing
        )
        try await fixture.prePopulate(nonce: "nonce-abc")
        fixture.http.install(
            path: "/v1/session/revoke",
            response: .json(
                ["code": "internal_server_error", "message": "boom"],
                statusCode: 500
            )
        )

        do {
            try await fixture.client.logout()
            XCTFail("expected logout to throw when both wipe and /revoke fail")
        } catch let error as SessionTokenStoreError {
            guard case let .keychainFailure(status) = error else {
                XCTFail("expected keychainFailure, got \(error)")
                return
            }
            XCTAssertEqual(
                status,
                errSecIO,
                "wipe error should win over the /revoke 500"
            )
        } catch {
            XCTFail(
                "expected SessionTokenStoreError.keychainFailure (wipe error), "
                    + "got \(error) — /revoke error must not mask the partial wipe"
            )
        }

        // /revoke is still attempted before we rethrow the wipe
        // error. Surfacing the wipe error is about which one wins,
        // not about skipping the server round-trip.
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/revoke"), 1)
        XCTAssertNotNil(try fixture.refreshTokenStore.get(domain: domain))
        XCTAssertNil(try fixture.keyStore.get(domain: domain))
        XCTAssertNil(try fixture.keyStore.getNonce(domain: domain))
        let cached2 = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(cached2)
    }

    /// A `refresh()` triggered during `/revoke`'s suspension can't
    /// resurrect the session: ``doRefresh`` short-circuits on the
    /// missing refresh token and throws ``unauthorized`` without
    /// touching the network.
    func test_concurrentRefreshDuringLogout_cannotResurrect() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        fixture.http.install(path: "/v1/session/revoke", response: .noContent)
        fixture.http.installGate(path: "/v1/session/revoke")

        let logout = Task { try await fixture.client.logout() }
        try await waitUntil { fixture.http.requestCount(forPath: "/v1/session/revoke") >= 1 }

        do {
            _ = try await fixture.client.refresh()
            XCTFail("racing refresh should have failed without a token")
        } catch PreludeAuthError.unauthorized {
            // expected
        }

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/refresh"),
            0,
            "post-wipe refresh must not hit the network"
        )

        fixture.http.releaseGate(path: "/v1/session/revoke")
        try await logout.value

        let cached3 = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(cached3)
        XCTAssertNil(try fixture.refreshTokenStore.get(domain: domain))
    }

    // MARK: - Helpers

    private func waitUntil(
        timeout: TimeInterval = 2,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ condition: @escaping () -> Bool
    ) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if condition() {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out", file: file, line: line)
    }

    /// Well-formed but unsigned JWT. `JWT.decode` parses payload only.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"
}

// MARK: - Stub HTTP session

/// Maps a path to a canned response, records every request, and
/// can suspend a response until ``releaseGate(path:)``.
final class StubHTTPSession: HTTPSession, @unchecked Sendable {
    struct CannedResponse {
        var statusCode: Int
        var body: Data
        var headers: [String: String]

        static let noContent = Self(statusCode: 204, body: Data(), headers: [:])

        static func json(
            _ body: [String: Any],
            statusCode: Int = 200,
            headers: [String: String] = [:]
        ) -> Self {
            let data = (try? JSONSerialization.data(withJSONObject: body)) ?? Data()
            var merged = ["Content-Type": "application/json"]
            for (key, value) in headers {
                merged[key] = value
            }
            return Self(statusCode: statusCode, body: data, headers: merged)
        }
    }

    private let lock = NSLock()
    private var byPath: [String: CannedResponse] = [:]
    // Per-path FIFO of canned responses; consumed before `byPath`.
    // Used by tests that need different responses across hops on
    // the same path (e.g. proactive-refresh: 401 → 200).
    private var sequences: [String: [CannedResponse]] = [:]
    private var recordedRequests: [URLRequest] = []
    private var gatedPaths: Set<String> = []
    private var pendingGates: [String: [CheckedContinuation<Void, Never>]] = [:]

    func install(path: String, response: CannedResponse) {
        lock.withLock { byPath[path] = response }
    }

    /// Queue a FIFO of canned responses for `path`. Each request
    /// pops the head; once empty, the stub falls back to whatever
    /// `install(path:response:)` last set for that path.
    func installSequence(path: String, responses: [CannedResponse]) {
        lock.withLock { sequences[path] = responses }
    }

    func installGate(path: String) {
        lock.withLock { _ = gatedPaths.insert(path) }
    }

    func releaseGate(path: String) {
        let waiters: [CheckedContinuation<Void, Never>] = lock.withLock {
            gatedPaths.remove(path)
            return pendingGates.removeValue(forKey: path) ?? []
        }
        for waiter in waiters {
            waiter.resume()
        }
    }

    func requestCount(forPath path: String) -> Int {
        lock.withLock { recordedRequests.filter { $0.url?.path == path }.count }
    }

    func requests(forPath path: String) -> [URLRequest] {
        lock.withLock { recordedRequests.filter { $0.url?.path == path } }
    }

    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let path = request.url?.path ?? ""

        let (shouldWait, canned): (Bool, CannedResponse?) = lock.withLock {
            recordedRequests.append(request)
            // Sequence head wins over the single-shot map so tests
            // can override one hop without disturbing the rest.
            if var queue = sequences[path], !queue.isEmpty {
                let head = queue.removeFirst()
                sequences[path] = queue
                return (gatedPaths.contains(path), head)
            }
            return (gatedPaths.contains(path), byPath[path])
        }

        if shouldWait {
            // Re-check inside the continuation body closes the race
            // where `releaseGate` ran between our check above and
            // the continuation being registered.
            await withCheckedContinuation { cont in
                let resumeImmediately: Bool = lock.withLock {
                    if gatedPaths.contains(path) {
                        pendingGates[path, default: []].append(cont)
                        return false
                    }
                    return true
                }
                if resumeImmediately { cont.resume() }
            }
        }

        guard let canned else { throw URLError(.unsupportedURL) }

        guard let response = HTTPURLResponse(
            url: request.url ?? URL(string: "about:blank")!,
            statusCode: canned.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: canned.headers
        ) else {
            throw URLError(.cannotParseResponse)
        }

        return (canned.body, response)
    }
}

// MARK: - Failing-delete backend

/// Wraps a ``KeychainBackend`` so ``delete(_:)`` returns `errSecIO`
/// when the query's `kSecAttrService` matches. Drives
/// ``PreludeAuthClient/clearAllStores()`` into its
/// partial-failure path.
final class FailingDeleteBackend: KeychainBackend, @unchecked Sendable {
    let underlying: KeychainBackend
    let failDeleteForService: String

    init(underlying: KeychainBackend, failDeleteForService: String) {
        self.underlying = underlying
        self.failDeleteForService = failDeleteForService
    }

    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef? {
        try underlying.copyMatching(query)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        underlying.add(attributes)
    }

    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus {
        underlying.update(query, attributesToUpdate: attributesToUpdate)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        if let service = query[kSecAttrService as String] as? String,
           service == failDeleteForService {
            return errSecIO
        }
        return underlying.delete(query)
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        try underlying.createRandomKey(attributes)
    }
}

// MARK: - NSLock closure helper

extension NSLock {
    private func withLock<T>(_ body: () -> T) -> T {
        lock()
        defer { unlock() }
        return body()
    }
}

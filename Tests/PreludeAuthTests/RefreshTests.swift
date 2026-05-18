import Foundation
@testable import PreludeAuth
import XCTest

/// `/refresh` round-trip contract: header-based refresh token +
/// rotation, DPoP nonce reuse, clock-skew adjustment, 401 = no
/// store wipe, single-flight coalescing.
final class RefreshTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "refresh-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_700_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    /// Well-formed unsigned JWT — `JWT.decode` reads payload only.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    // MARK: - Headers + rotation

    /// Refresh token rides as `X-Refresh-Token` (not body, not
    /// cookie); the response rotation replaces it; the next call
    /// sends the rotated value.
    func test_refresh_rotatesToken_andUsesRotatedValueOnNextCall() async throws {
        let fixture = try makeFixture()
        try await fixture.prePopulate(accessTokenExpired: true) // refresh-v1

        installRefresh(fixture: fixture, rotateTo: "refresh-v2")
        _ = try await fixture.client.refresh()

        let firstReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/refresh").first)
        XCTAssertEqual(firstReq.value(forHTTPHeaderField: HTTPHeader.refreshToken), "refresh-v1")
        XCTAssertNil(firstReq.httpBody, "plain refresh has no body — refresh token rides as header")
        XCTAssertNil(firstReq.value(forHTTPHeaderField: "Cookie"), "SDK must not set Cookie")
        XCTAssertEqual(try fixture.refreshTokenStore.get(domain: domain)?.refreshToken, "refresh-v2")

        // Force another refresh: rotated value must be what goes out.
        try await fixture.client.invalidateSession()
        installRefresh(fixture: fixture, rotateTo: "refresh-v3")
        _ = try await fixture.client.refresh()

        let secondReq = fixture.http.requests(forPath: "/v1/session/refresh").last
        XCTAssertEqual(secondReq?.value(forHTTPHeaderField: HTTPHeader.refreshToken), "refresh-v2")
        XCTAssertEqual(try fixture.refreshTokenStore.get(domain: domain)?.refreshToken, "refresh-v3")
    }

    // MARK: - DPoP nonce reuse

    /// Warm nonce → proof carries it on the first hop, no
    /// `use_dpop_nonce` retry. Guards steady-state cost.
    func test_refresh_warmNonce_completesInOneRoundTrip() async throws {
        let fixture = try makeFixture()
        try await fixture.prePopulate(nonce: "warm-nonce", accessTokenExpired: true)

        installRefresh(fixture: fixture, rotateTo: "refresh-v2")
        _ = try await fixture.client.refresh()

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
    }

    // MARK: - Clock-skew adjustment on the refresh path

    /// 5-min skew on `Date:` propagates into the cached expiry.
    /// Pins the response → cache wiring on the refresh path.
    func test_refresh_appliesClockSkew_fromDateHeader() async throws {
        let fixture = try makeFixture()
        try await fixture.prePopulate(accessTokenExpired: true)

        let serverExpiresAt = Int(clock().timeIntervalSince1970) + 3600
        // Server's `Date:` is 5 min behind the client clock → skew = +300s.
        let serverDate = Date(timeIntervalSince1970: clock().timeIntervalSince1970 - 300)
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                ["access_token": jwt, "expires_at": serverExpiresAt],
                headers: [
                    HTTPHeader.refreshToken: "refresh-v2",
                    HTTPHeader.date: Self.imfDate(serverDate),
                ]
            )
        )
        _ = try await fixture.client.refresh()

        let cached = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(cached?.expiresAt, serverExpiresAt + 300, "expiry must include +300s skew")
    }

    // MARK: - 401 handling

    /// 401 (revoked / replayed) → `.unauthorized`, store untouched
    /// (caller decides on logout), exactly one round-trip (no
    /// DPoP retry for non-`use_dpop_nonce` 401s).
    func test_refresh_401_throwsUnauthorized_storeUntouched_singleRoundTrip() async throws {
        let fixture = try makeFixture()
        try await fixture.prePopulate(accessTokenExpired: true)

        let body = try JSONSerialization.data(withJSONObject: [
            "code": "unauthorized",
            "display_message": "refresh token revoked",
        ])
        fixture.http.install(
            path: "/v1/session/refresh",
            response: StubHTTPSession.CannedResponse(
                statusCode: 401, body: body, headers: ["Content-Type": "application/json"]
            )
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("expected unauthorized")
        } catch PreludeAuthError.unauthorized {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertEqual(
            try fixture.refreshTokenStore.get(domain: domain)?.refreshToken,
            "refresh-v1",
            "401 must not wipe the store; caller decides on logout"
        )
    }

    // MARK: - Single-flight

    /// Concurrent callers coalesce — the single-use refresh token
    /// is redeemed once. Gate, fan out, release, assert.
    func test_refresh_concurrentCallers_coalesceOntoOneRoundTrip() async throws {
        let fixture = try makeFixture()
        try await fixture.prePopulate(accessTokenExpired: true)

        installRefresh(fixture: fixture, rotateTo: "refresh-v2")
        fixture.http.installGate(path: "/v1/session/refresh")

        async let firstRefresh = fixture.client.refresh()
        async let secondRefresh = fixture.client.refresh()
        async let thirdRefresh = fixture.client.refresh()
        try await waitUntil { fixture.http.requestCount(forPath: "/v1/session/refresh") >= 1 }
        fixture.http.releaseGate(path: "/v1/session/refresh")

        let users = try await [firstRefresh, secondRefresh, thirdRefresh]
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertEqual(Set(users.map(\.accessToken)).count, 1, "all callers see the same token")
        XCTAssertEqual(try fixture.refreshTokenStore.get(domain: domain)?.refreshToken, "refresh-v2")
    }

    // MARK: - Helpers

    private func makeFixture() throws -> Fixture {
        try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
    }

    private func installRefresh(fixture: Fixture, rotateTo: String) {
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: rotateTo]
            )
        )
    }

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

    /// RFC 7231 IMF-fixdate, matching `HTTPClient`'s parser.
    private static func imfDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }
}

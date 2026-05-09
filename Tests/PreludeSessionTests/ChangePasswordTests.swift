import Foundation
import XCTest
@testable import PreludeSession

final class ChangePasswordTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "change-pwd-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    /// Payload: `{"sub":"user-1","sid":"sess-1"}` — same shape
    /// /refresh would mint, just without `prld:pwd:write`.
    private let freshAccessToken =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    // MARK: - Happy path

    func test_changePassword_success_invalidatesCache_andRefreshes() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .noContent
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": freshAccessToken,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        try await fixture.client.changePassword(RedactedString("new-secret-password"))

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/me/password/reset"),
            1
        )
        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/refresh"),
            1
        )

        let cachedAfter = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(cachedAfter?.accessToken, freshAccessToken)
    }

    // MARK: - Error mapping

    func test_changePassword_insufficientScope_throwsStructured_noRefresh() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .json(
                ["code": "insufficient_scope", "message": "need prld:pwd:write"],
                statusCode: 403
            )
        )

        do {
            try await fixture.client.changePassword(RedactedString("new-password"))
            XCTFail("expected insufficientScope")
        } catch PreludeSessionError.insufficientScope {
            // expected
        }

        // Refresh must not run when the change fails.
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 0)
    }

    func test_changePassword_invalidPassword_throwsStructured() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .json(
                ["code": "invalid_password", "message": "too weak"],
                statusCode: 400
            )
        )

        do {
            try await fixture.client.changePassword(RedactedString("weak"))
            XCTFail("expected invalidPassword")
        } catch PreludeSessionError.invalidPassword {
            // expected
        }
    }

    // MARK: - Non-fatal refresh

    func test_changePassword_refreshFails_stillReturnsSuccess_butCacheInvalidated() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .noContent
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                ["code": "internal_server_error", "message": "boom"],
                statusCode: 500
            )
        )

        // Does NOT throw — the password change succeeded; the
        // follow-up refresh failure is non-fatal.
        try await fixture.client.changePassword(RedactedString("new-secret-password"))

        // The cached token was invalidated before the failed
        // refresh, so the next protected call will auto-refresh.
        let cached = await fixture.accessTokenCache.get(domain: domain)
        XCTAssertNil(cached)
    }

    // MARK: - DPoP attachment policy

    /// `/me/password/reset` is bearer-authenticated — only
    /// the `Authorization` middleware runs on it. Sending a
    /// DPoP proof would be ignored at best and rejected by
    /// strict proxies at worst. Pin the absence so a future
    /// refactor can't reintroduce it.
    func test_changePassword_doesNotAttachDPoPHeader() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .noContent
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": freshAccessToken,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        try await fixture.client.changePassword(RedactedString("new-secret-password"))

        let recorded = fixture.http.requests(forPath: "/v1/session/me/password/reset")
        XCTAssertEqual(recorded.count, 1)
        XCTAssertNil(
            recorded.first?.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/me/password/reset is bearer-authenticated; DPoP must not be attached"
        )
    }

    /// Positive side: the access token must still ride along as
    /// `Authorization: Bearer <token>`. Pinning this prevents an
    /// over-eager "remove DPoP from /me/*" sweep from dropping
    /// the bearer too.
    func test_changePassword_attachesAuthorizationBearer() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .noContent
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": freshAccessToken,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        try await fixture.client.changePassword(RedactedString("new-secret-password"))

        let recorded = fixture.http.requests(forPath: "/v1/session/me/password/reset")
        XCTAssertEqual(recorded.count, 1)
        let auth = recorded.first?.value(forHTTPHeaderField: HTTPHeader.authorization)
        XCTAssertNotNil(auth, "/me/password/reset must carry Authorization: Bearer")
        XCTAssertEqual(auth, "Bearer access-v1", "must carry the cached access token verbatim")
    }
}

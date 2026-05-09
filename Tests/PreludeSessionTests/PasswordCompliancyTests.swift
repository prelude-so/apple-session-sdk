import Foundation
import XCTest
@testable import PreludeSession

final class PasswordCompliancyTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "pwd-compliancy-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    func test_passwordCompliancy_decodesAllFields() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        fixture.http.install(
            path: "/v1/session/password/compliancy",
            response: .json([
                "min_length": 8,
                "max_length": 64,
                "uppercase": 1,
                "lowercase": 1,
                "numbers": 1,
                "symbols": 0,
            ])
        )

        let compliancy = try await fixture.client.passwordCompliancy()

        XCTAssertEqual(
            compliancy,
            PreludePasswordCompliancy(
                minLength: 8,
                maxLength: 64,
                uppercase: 1,
                lowercase: 1,
                numbers: 1,
                symbols: 0
            )
        )

        // GET, not POST — the default request builder posts.
        let recorded = fixture.http.requests(forPath: "/v1/session/password/compliancy")
        XCTAssertEqual(recorded.count, 1)
        XCTAssertEqual(recorded.first?.httpMethod, "GET")

        // No body, no Content-Type. Strict proxies reject a
        // Content-Type on a bodyless request.
        XCTAssertNil(recorded.first?.value(forHTTPHeaderField: "Content-Type"))
        XCTAssertEqual(recorded.first?.value(forHTTPHeaderField: "Accept"), "application/json")
    }

    // MARK: - Unauthenticated route

    /// No DPoP, no Bearer — the rules are public configuration.
    func test_passwordCompliancy_isUnauthenticated() async throws {
        let fixture = try makeFixtureWithCompliancy()
        try await fixture.prePopulate() // populate access token + key

        _ = try await fixture.client.passwordCompliancy()

        let req = try XCTUnwrap(
            fixture.http.requests(forPath: "/v1/session/password/compliancy").first
        )
        XCTAssertNil(req.value(forHTTPHeaderField: HTTPHeader.dpop))
        XCTAssertNil(req.value(forHTTPHeaderField: HTTPHeader.authorization))
    }

    // MARK: - No retry on use_dpop_nonce

    /// Unauthenticated route: a `use_dpop_nonce` reply must not
    /// trigger a retry — there's no nonce dance to advance, and a
    /// retrying interceptor here would loop.
    func test_passwordCompliancy_useDpopNonce_doesNotRetry() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/password/compliancy",
            response: .json(
                ["code": "use_dpop_nonce", "message": "rotate"],
                statusCode: 400,
                headers: [HTTPHeader.dpopNonce: "n1"]
            )
        )

        do {
            _ = try await fixture.client.passwordCompliancy()
            XCTFail("expected error")
        } catch {}

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/password/compliancy"), 1
        )
    }

    // MARK: - No side effects

    /// Successful call must not touch the access-token cache and
    /// must not fire `/refresh`.
    func test_passwordCompliancy_hasNoSideEffects() async throws {
        let fixture = try makeFixtureWithCompliancy()
        try await fixture.prePopulate()

        let before = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)

        _ = try await fixture.client.passwordCompliancy()

        let after = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(before?.accessToken, after?.accessToken)
        XCTAssertEqual(before?.expiresAt, after?.expiresAt)
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 0)
    }

    // MARK: - Helpers

    private func makeFixtureWithCompliancy() throws -> Fixture {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/password/compliancy",
            response: .json([
                "min_length": 8, "max_length": 64,
                "uppercase": 1, "lowercase": 1, "numbers": 1, "symbols": 0,
            ])
        )
        return fixture
    }
}

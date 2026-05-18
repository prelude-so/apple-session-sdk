import Foundation
@testable import PreludeAuth
import XCTest

/// End-to-end behavior of `AutoRefreshInterceptor` driven through
/// a real protected call (`/stepup/request`):
///
///   - one 401 triggers exactly one `/refresh` and one replay.
///   - if `/refresh` itself fails, the original 401 surfaces and
///     there is no loop.
///   - two concurrent 401s coalesce on a single `/refresh` and
///     both retries carry the rotated bearer.
///
/// `/stepup/request` is convenient because the `block` status
/// short-circuits before any OTP delivery side-effects.
final class AutoRefreshInterceptorTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "auto-refresh-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private let scopedJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s"

    // MARK: - 401 → 1× refresh → replay

    func test_protected401_triggersOneRefresh_andReplaysOriginal() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate() // valid access token "access-v1"

        fixture.http.installSequence(
            path: "/v1/session/stepup/request",
            responses: [unauthorized(), .json(["status": "block"])]
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: refreshOK(rotateTo: "refresh-v2", access: scopedJWT)
        )

        _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        let stepup = fixture.http.requests(forPath: "/v1/session/stepup/request")
        XCTAssertEqual(stepup.count, 2)
        XCTAssertEqual(
            stepup[0].value(forHTTPHeaderField: HTTPHeader.authorization),
            "Bearer access-v1"
        )
        XCTAssertEqual(
            stepup[1].value(forHTTPHeaderField: HTTPHeader.authorization),
            "Bearer \(scopedJWT)",
            "replay must carry the rotated bearer"
        )
    }

    // MARK: - Refresh fails → original 401, no loop

    func test_protected401_refreshAlsoFails_surfacesOriginal401_noLoop() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/stepup/request", response: unauthorized())
        try fixture.http.install(
            path: "/v1/session/refresh",
            response: StubHTTPSession.CannedResponse(
                statusCode: 401,
                body: JSONSerialization.data(withJSONObject: [
                    "code": "invalid_grant", "message": "spent",
                ]),
                headers: ["Content-Type": "application/json"]
            )
        )

        do {
            _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
            XCTFail("expected unauthorized")
        } catch PreludeAuthError.unauthorized {}

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/stepup/request"), 1,
            "no replay when /refresh itself fails"
        )
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
    }

    // MARK: - Concurrent protected calls coalesce

    /// Two concurrent protected calls both hit 401. The single-
    /// flight refresher dedupes the `/refresh` round-trip; both
    /// retries carry the rotated bearer.
    func test_concurrentProtectedCalls_coalesceOntoOneRefresh() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        // First two hits return 401 (one per concurrent caller);
        // every later hit (the two retries) falls through to the
        // single-shot 200.
        fixture.http.installSequence(
            path: "/v1/session/stepup/request",
            responses: [unauthorized(), unauthorized()]
        )
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "block"])
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: refreshOK(rotateTo: "refresh-v2", access: scopedJWT)
        )

        async let firstRequest = fixture.client.requestStepUp(scope: "prld:pwd:write")
        async let secondRequest = fixture.client.requestStepUp(scope: "prld:pwd:write")
        _ = try await [firstRequest, secondRequest]

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/refresh"), 1,
            "single-flight refresh"
        )
        let stepup = fixture.http.requests(forPath: "/v1/session/stepup/request")
        XCTAssertEqual(stepup.count, 4, "2 initial 401s + 2 retries")
        let retries = Array(stepup[2...])
        for req in retries {
            XCTAssertEqual(
                req.value(forHTTPHeaderField: HTTPHeader.authorization),
                "Bearer \(scopedJWT)",
                "every retry must carry the rotated bearer"
            )
        }
    }

    // MARK: - Helpers

    private func unauthorized() -> StubHTTPSession.CannedResponse {
        let body = (try? JSONSerialization.data(withJSONObject: [
            "code": "unauthorized", "message": "expired",
        ])) ?? Data()
        return StubHTTPSession.CannedResponse(
            statusCode: 401, body: body,
            headers: ["Content-Type": "application/json"]
        )
    }

    private func refreshOK(rotateTo: String, access: String) -> StubHTTPSession.CannedResponse {
        .json(
            [
                "access_token": access,
                "expires_at": Int(clock().timeIntervalSince1970) + 3600,
            ],
            headers: [HTTPHeader.refreshToken: rotateTo]
        )
    }
}

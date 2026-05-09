import Foundation
import XCTest
@testable import PreludeSession

/// Inflight-slot hygiene around `refresh()`. The slot is cleared
/// via `defer` inside the refresh task, so a network-drop or any
/// other thrown error must not leave a zombie task behind that
/// future callers join.
final class RefreshInflightTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "refresh-inflight-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_700_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s"

    /// First refresh fails (network drop); the second call must
    /// hit the wire — proving the inflight slot was cleared on
    /// throw and the second caller didn't join the dead task.
    func test_refreshFailure_clearsInflight_secondCallRetries() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        fixture.http.installSequence(
            path: "/v1/session/refresh",
            responses: [
                StubHTTPSession.CannedResponse(
                    statusCode: 503,
                    body: try JSONSerialization.data(withJSONObject: [
                        "code": "internal_server_error", "message": "drop",
                    ]),
                    headers: ["Content-Type": "application/json"]
                ),
                .json(
                    ["access_token": jwt,
                     "expires_at": Int(clock().timeIntervalSince1970) + 3600],
                    headers: [HTTPHeader.refreshToken: "r2"]
                ),
            ]
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("first refresh should fail")
        } catch {}

        // Inflight slot must be clear by the time the first call
        // throws; the next call must retry rather than join a
        // dead task.
        let inflight = await fixture.client.impl.inflightRefresh
        XCTAssertNil(inflight, "inflight slot must be cleared after a thrown refresh")

        _ = try await fixture.client.refresh()
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 2)
    }
}

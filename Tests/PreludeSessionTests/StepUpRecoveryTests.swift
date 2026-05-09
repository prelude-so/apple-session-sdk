import Foundation
import XCTest
@testable import PreludeSession

/// Recovery + defensive paths around `/stepup/request`:
///
///   - 401 on `/stepup/request` triggers the auto-refresh
///     interceptor, then a retry — caller sees one transparent
///     success, two `/stepup/request` hits, one `/refresh`.
///   - A `completed`-step response from `/stepup/request` is a
///     server contract violation; throw before any post-
///     completion refresh fires.
///   - After a local short-circuit on an expired challenge the
///     client is still healthy: a fresh `requestStepUp` issues
///     a new challenge cleanly.
final class StepUpRecoveryTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "stepup-recovery-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private var otpChallengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "verify_email",
            "jti": "jti-otp", "exp": 2_000_000,
        ])
    }

    private let scopedJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    // MARK: - Proactive refresh on /stepup/request

    /// 401 → refresh → retry must land transparently. Pin the
    /// counts + final return value so a regression that drops
    /// `autoRefreshInterceptor` from `requestStepUp` surfaces as
    /// a failed test, not a user-visible auth failure.
    func test_requestStepUp_proactiveRefreshAfter401() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let unauthorized = StubHTTPSession.CannedResponse(
            statusCode: 401,
            body: try JSONSerialization.data(withJSONObject: [
                "code": "unauthorized", "display_message": "expired bearer",
            ]),
            headers: ["Content-Type": "application/json"]
        )
        fixture.http.installSequence(
            path: "/v1/session/stepup/request",
            responses: [
                unauthorized,
                .json(["status": "continue", "challenge_token": otpChallengeToken]),
            ]
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                ["access_token": scopedJWT, "expires_at": Int(clock().timeIntervalSince1970) + 3600],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        XCTAssertEqual(challenge.challengeID, "chal-1")
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/stepup/request"), 2)
    }

    // MARK: - Completed-from-/stepup/request

    /// Defensive: throw before any post-completion refresh fires.
    /// Otherwise the rotation lands on a handle the SDK would
    /// later reject as expired.
    func test_requestStepUp_completedStep_throwsInvalidChallengeToken_noRefresh() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let completed = StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "completed",
            "jti": "jti-completed", "exp": 2_000_000,
        ])
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": completed])
        )

        do {
            _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
            XCTFail("expected invalidChallengeToken")
        } catch PreludeSessionError.invalidChallengeToken {}

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/refresh"), 0,
            "defensive throw must fire before any post-completion refresh"
        )
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 0)
    }

    // MARK: - Recovery after expired short-circuit

    /// Local expiry guard rejects without hitting the wire; the
    /// next `requestStepUp` succeeds with a fresh challenge.
    /// Without this, a caller hitting the expiry edge would be
    /// wedged.
    func test_requestStepUp_recoversCleanly_afterExpiredChallengeShortCircuit() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let expired = StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-old", "current_step": "verify_email",
            "jti": "jti-old", "exp": 999_999,
        ])
        fixture.http.installSequence(
            path: "/v1/session/stepup/request",
            responses: [
                .json(["status": "continue", "challenge_token": expired]),
                .json(["status": "continue", "challenge_token": otpChallengeToken]),
            ]
        )

        let stale = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        do {
            _ = try await fixture.client.submitStepUpOTP(stale, code: "123456")
            XCTFail("expected invalidChallengeToken")
        } catch PreludeSessionError.invalidChallengeToken {}
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp/check"), 0)

        let fresh = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        XCTAssertEqual(fresh.challengeID, "chal-1")
        XCTAssertEqual(fresh.token, otpChallengeToken)
    }
}

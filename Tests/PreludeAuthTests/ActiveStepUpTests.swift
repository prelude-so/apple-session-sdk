import Foundation
@testable import PreludeAuth
import XCTest

/// `activeStepUp` lifecycle: set on `requestStepUp`, advanced on
/// multi-step `submitStepUpOTP`, cleared on completion / logout /
/// `changePassword`.
final class ActiveStepUpTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "active-stepup-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private let scopedJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private var otpChallengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "verify_email",
            "jti": "jti-otp", "exp": 2_000_000,
        ])
    }

    private var smsChallengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "verify_sms",
            "jti": "jti-sms", "exp": 2_000_000,
        ])
    }

    private var completedChallengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "completed",
            "jti": "jti-completed", "exp": 2_000_000,
        ])
    }

    // MARK: - Set / advance / clear

    func test_activeStepUp_setOnRequest_advancedOnSubmit_clearedOnCompletion() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": otpChallengeToken])
        )
        fixture.http.installSequence(
            path: "/v1/session/otp/check",
            responses: [
                .json(["challenge_token": smsChallengeToken]),
                .json(["challenge_token": completedChallengeToken]),
            ]
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": scopedJWT,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        var current = await fixture.client.activeStepUp
        XCTAssertNil(current)

        let first = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        current = await fixture.client.activeStepUp
        XCTAssertEqual(current?.token, otpChallengeToken)

        let next = try await fixture.client.submitStepUpOTP(first, code: "111111")
        XCTAssertEqual(next?.currentStep, "verify_sms")
        current = await fixture.client.activeStepUp
        XCTAssertEqual(current?.token, smsChallengeToken)

        _ = try await fixture.client.submitStepUpOTP(XCTUnwrap(next), code: "222222")
        current = await fixture.client.activeStepUp
        XCTAssertNil(current, "completion must clear the handle")
    }

    // MARK: - Blocked

    func test_activeStepUp_setForBlockedStatus() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "block"])
        )

        _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        let blocked = await fixture.client.activeStepUp
        XCTAssertEqual(blocked?.status, .blocked)
    }

    // MARK: - Logout clears

    func test_activeStepUp_clearedOnLogout() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": otpChallengeToken])
        )
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        let beforeLogout = await fixture.client.activeStepUp
        XCTAssertNotNil(beforeLogout)

        try await fixture.client.logout()
        let afterLogout = await fixture.client.activeStepUp
        XCTAssertNil(afterLogout)
    }

    // MARK: - changePassword clears (success + failure)

    func test_activeStepUp_clearedAfterChangePasswordSuccess() async throws {
        let fixture = try await makeWithStaleHandle()
        fixture.http.install(path: "/v1/session/me/password/reset", response: .noContent)
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": scopedJWT,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        try await fixture.client.changePassword(RedactedString("new-secret-password"))
        let after = await fixture.client.activeStepUp
        XCTAssertNil(after)
    }

    func test_activeStepUp_clearedAfterChangePasswordFailure() async throws {
        let fixture = try await makeWithStaleHandle()
        fixture.http.install(
            path: "/v1/session/me/password/reset",
            response: .json(
                ["code": "invalid_password", "message": "weak"], statusCode: 400
            )
        )

        do {
            try await fixture.client.changePassword(RedactedString("weak"))
            XCTFail("expected invalidPassword")
        } catch PreludeAuthError.invalidPassword {}

        let after = await fixture.client.activeStepUp
        XCTAssertNil(after, "handle must clear on failure too — caller must restart step-up")
    }

    // MARK: - Helpers

    /// Fixture with `activeStepUp` pre-populated via a real
    /// `requestStepUp` round-trip — closer to production state
    /// than poking the actor directly.
    private func makeWithStaleHandle() async throws -> Fixture {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": otpChallengeToken])
        )

        _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        return fixture
    }
}

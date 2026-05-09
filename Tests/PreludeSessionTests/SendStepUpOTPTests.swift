import Foundation
import XCTest
@testable import PreludeSession

/// Caller-driven OTP delivery: ``PreludeSessionClient/sendStepUpOTP(_:)``
/// fires `POST /otp` for an in-flight step-up challenge. The SDK
/// no longer auto-delivers from ``requestStepUp(scope:)`` /
/// ``submitStepUpOTP(_:code:)``; callers must invoke this
/// explicitly.
final class SendStepUpOTPTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "send-stepup-otp-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private var otpChallengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1",
            "current_step": "verify_email",
            "jti": "jti-otp",
            "exp": 2_000_000,
        ])
    }

    func test_sendStepUpOTP_firesOTP_withChallengeToken() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": otpChallengeToken])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/otp"), 0,
            "requestStepUp must not auto-fire /otp"
        )

        try await fixture.client.sendStepUpOTP(challenge)

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 1)
        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp").first)
        let body = try XCTUnwrap(req.httpBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        XCTAssertEqual(json?["challenge_token"] as? String, otpChallengeToken)
    }

    /// Blocked challenges carry no token — short-circuit before any
    /// network call so the server doesn't see an empty
    /// `challenge_token` and 400.
    func test_sendStepUpOTP_blockedChallenge_throwsInvalidChallengeToken_noRoundTrip() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let blocked = StepUpChallenge.blocked(requestedScope: "prld:pwd:write")

        do {
            try await fixture.client.sendStepUpOTP(blocked)
            XCTFail("expected invalidChallengeToken")
        } catch PreludeSessionError.invalidChallengeToken {
            // expected
        }
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 0)
    }

    /// `/otp` is unauthenticated on the wire — the challenge token
    /// in the body identifies the caller. No bearer (could leak a
    /// cached access token) and no DPoP proof.
    func test_sendStepUpOTP_doesNotAttachAuthorizationOrDPoP() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate() // populates a valid access token

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": otpChallengeToken])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        try await fixture.client.sendStepUpOTP(challenge)

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp").first)
        XCTAssertNil(
            req.value(forHTTPHeaderField: HTTPHeader.authorization),
            "/otp must not carry Authorization"
        )
        XCTAssertNil(
            req.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/otp must not carry a DPoP proof"
        )
    }
}

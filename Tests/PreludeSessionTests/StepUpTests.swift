import Foundation
import XCTest
@testable import PreludeSession

/// ``requestStepUp`` returns a value-typed ``StepUpChallenge``,
/// the caller passes it back to ``submitStepUpOTP``, and the SDK
/// holds no step-up state across calls. That last property is
/// what makes concurrent flows trivially safe.
final class StepUpTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "stepup-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    // MARK: - Stable challenge tokens

    private var otpChallengeToken: String {
        Self.makeChallengeToken([
            "challenge_id": "chal-1",
            "current_step": "verify_email",
            "jti": "jti-otp",
            "exp": 2_000_000,
        ])
    }

    private var completedChallengeToken: String {
        Self.makeChallengeToken([
            "challenge_id": "chal-1",
            "current_step": "completed",
            "jti": "jti-completed",
            "exp": 2_000_000,
        ])
    }

    /// Payload: `{"sub":"user-1","sid":"sess-1"}`.
    private let scopedAccessToken =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    // MARK: - requestStepUp

    func test_requestStepUp_otpStep_returnsChallenge_andAutoKicksOTP() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": otpChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        let challenge = try await fixture.client.requestStepUp(
            scope: "prld:pwd:write"
        )

        XCTAssertEqual(challenge.status, .continue)
        XCTAssertEqual(challenge.challengeID, "chal-1")
        XCTAssertEqual(challenge.currentStep, "verify_email")
        XCTAssertEqual(challenge.requestedScope, "prld:pwd:write")
        XCTAssertEqual(challenge.token, otpChallengeToken)

        // Auto-kick: /otp fired in the same call.
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 1)
    }

    func test_requestStepUp_blocked_returnsBlockedChallenge_noOTPKicked() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "block"])
        )

        let challenge = try await fixture.client.requestStepUp(
            scope: "prld:pwd:write"
        )

        XCTAssertEqual(challenge.status, .blocked)
        XCTAssertEqual(challenge.requestedScope, "prld:pwd:write")
        XCTAssertEqual(challenge.token, "", "blocked challenge must not carry a token")
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 0)
    }

    func test_requestStepUp_scopeNotAllowed_throwsForbidden() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(
                ["code": "scope_not_allowed", "message": "no"],
                statusCode: 403
            )
        )

        do {
            _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
            XCTFail("expected forbidden")
        } catch PreludeSessionError.forbidden {
            // expected
        }
    }

    // MARK: - submitStepUpOTP

    func test_submitStepUpOTP_blockedChallenge_throwsInvalidChallengeToken_noRoundTrip() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let blocked = StepUpChallenge.blocked(requestedScope: "prld:pwd:write")

        do {
            _ = try await fixture.client.submitStepUpOTP(blocked, code: "123456")
            XCTFail("expected invalidChallengeToken")
        } catch PreludeSessionError.invalidChallengeToken {
            // expected — the SDK refuses a blocked challenge before
            // any network call.
        }
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp/check"), 0)
    }

    func test_submitStepUpOTP_completed_refreshesWithStepUpToken_returnsNil() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": otpChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": completedChallengeToken])
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": scopedAccessToken,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        let next = try await fixture.client.submitStepUpOTP(challenge, code: "123456")

        XCTAssertNil(next, "completed challenge should yield a nil follow-up")

        let refreshRequests = fixture.http.requests(forPath: "/v1/session/refresh")
        XCTAssertEqual(refreshRequests.count, 1)
        let body = try XCTUnwrap(refreshRequests.first?.httpBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: String]
        XCTAssertEqual(json?["step_up_token"], completedChallengeToken)

        let cachedAfter = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(cachedAfter?.accessToken, scopedAccessToken)
    }

    func test_submitStepUpOTP_badCheckCode_throwsInvalidOTPCode_challengeStillUsable() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": otpChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(
                ["code": "bad_check_code", "message": "wrong"],
                statusCode: 401
            )
        )

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")

        do {
            _ = try await fixture.client.submitStepUpOTP(challenge, code: "000000")
            XCTFail("expected invalidOTPCode")
        } catch PreludeSessionError.invalidOTPCode {
            // expected — `bad_check_code` is "retry the code", not
            // "re-login required".
        }

        // The caller's challenge value is unchanged and still
        // submittable up to the server's bucket limit.
        XCTAssertEqual(challenge.challengeID, "chal-1")
        XCTAssertEqual(challenge.token, otpChallengeToken)
    }

    /// A challenge whose `exp` is in the past must throw
    /// `invalidChallengeToken` before any /otp/check round-trip,
    /// so the UI can surface "expired, request a fresh one"
    /// distinctly from a mistyped OTP.
    func test_submitStepUpOTP_expiredChallenge_throwsInvalidChallengeToken_noRoundTrip() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let expiredChallengeToken = Self.makeChallengeToken([
            "challenge_id": "chal-1",
            "current_step": "verify_email",
            "jti": "jti-expired",
            "exp": 999_999,
        ])

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": expiredChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        XCTAssertEqual(
            challenge.expiresAt,
            999_999,
            "fixture should have produced a pre-expired challenge"
        )

        do {
            _ = try await fixture.client.submitStepUpOTP(challenge, code: "123456")
            XCTFail("expected invalidChallengeToken for an expired challenge")
        } catch PreludeSessionError.invalidChallengeToken {
            // expected
        }

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/otp/check"),
            0,
            "expired challenge must not produce a /otp/check round-trip"
        )
    }

    /// Multi-step OTP: the second step (`verify_sms`) must also
    /// auto-fire `POST /otp` — without symmetry the second
    /// delivery would silently not fire.
    func test_submitStepUpOTP_advancedOTPStep_autoKicksDelivery() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        let smsStepToken = Self.makeChallengeToken([
            "challenge_id": "chal-1",
            "current_step": "verify_sms",
            "jti": "jti-sms",
            "exp": 2_000_000,
        ])

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": otpChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": smsStepToken])
        )

        let first = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/otp"), 1,
            "first OTP delivery should have fired during requestStepUp"
        )

        let next = try await fixture.client.submitStepUpOTP(first, code: "123456")
        let advanced = try XCTUnwrap(next, "multi-step flow returns the next challenge")
        XCTAssertEqual(advanced.currentStep, "verify_sms")
        XCTAssertEqual(advanced.token, smsStepToken)

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/otp"), 2,
            "second OTP delivery should have fired during submitStepUpOTP"
        )
    }

    // MARK: - Concurrency

    /// With step-up state held by the caller (not the actor), a
    /// concurrent ``logout()`` has nothing to corrupt. Both flows
    /// run independently.
    func test_logoutDuringRequestStepUp_doesNotCorruptCallerHandle() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": otpChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)
        fixture.http.installGate(path: "/v1/session/stepup/request")

        let stepUp = Task {
            try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        }
        try await waitUntil {
            fixture.http.requestCount(forPath: "/v1/session/stepup/request") >= 1
        }

        try await fixture.client.logout()
        fixture.http.releaseGate(path: "/v1/session/stepup/request")

        let challenge = try await stepUp.value
        XCTAssertEqual(challenge.challengeID, "chal-1")
        XCTAssertEqual(challenge.token, otpChallengeToken)
    }

    /// On the post-completion refresh, ``submitStepUpOTP`` funnels
    /// through ``doRefresh``'s session-epoch guard. A logout that
    /// races surfaces as a clean ``unauthorized`` from the refresh.
    func test_logoutDuringSubmitCompletion_surfacesUnauthorizedFromRefresh() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json([
                "status": "continue",
                "challenge_token": otpChallengeToken,
            ])
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": completedChallengeToken])
        )
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": scopedAccessToken,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")

        // Hold /otp/check so logout can race the post-await
        // /refresh that submitStepUpOTP triggers on completion.
        fixture.http.installGate(path: "/v1/session/otp/check")

        let submit = Task {
            try await fixture.client.submitStepUpOTP(challenge, code: "123456")
        }
        try await waitUntil {
            fixture.http.requestCount(forPath: "/v1/session/otp/check") >= 1
        }

        try await fixture.client.logout()
        fixture.http.releaseGate(path: "/v1/session/otp/check")

        do {
            _ = try await submit.value
            XCTFail("expected unauthorized from the post-completion refresh")
        } catch PreludeSessionError.unauthorized {
            // expected
        }
    }

    // MARK: - Helpers

    /// Build a well-formed but unsigned JWT. `JWT.decode` reads
    /// header + payload only.
    private static func makeChallengeToken(_ claims: [String: Any]) -> String {
        let header = Data(#"{"alg":"HS256","typ":"JWT"}"#.utf8)
            .base64URLEncodedString()
        let payload = (try! JSONSerialization.data(
            withJSONObject: claims,
            options: [.sortedKeys]
        )).base64URLEncodedString()
        return "\(header).\(payload).sig"
    }

    private func waitUntil(
        timeout: TimeInterval = 2,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ condition: @escaping () -> Bool
    ) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if condition() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out", file: file, line: line)
    }
}

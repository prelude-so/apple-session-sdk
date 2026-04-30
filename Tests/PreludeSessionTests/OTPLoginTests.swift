import Foundation
import XCTest
@testable import PreludeSession

/// OTP-login flow tests, focused on the DPoP attachment policy:
///
/// `POST /otp`         → unauthenticated. No DPoP.
/// `POST /otp/check`   → unauthenticated; the OTP code in the body
///                       is the entire credential. No DPoP — there
///                       is no session-scoped key yet, and the
///                       challenge token only exists in the
///                       response.
/// `POST /login/finalize` → exchanges the challenge for the
///                          session tokens. DPoP **required**:
///                          this is where the issued tokens are
///                          bound to the device key.
final class OTPLoginTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "otp-login-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil
        baseURL = nil
        clock = nil
        super.tearDown()
    }

    // Well-formed, unsigned JWT — `JWT.decode` reads the payload only.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    // MARK: - DPoP attachment policy

    /// `/otp/check` is unauthenticated; the body's OTP code is the
    /// only credential. Sending DPoP would either be ignored or
    /// (worse, with strict proxies) rejected before the server
    /// could issue the challenge token. Guard the call site.
    func test_checkOTP_doesNotAttachDPoPHeader() async throws {
        let fixture = try makeFixture()

        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        _ = try await fixture.client.checkOTP("123456")

        let recorded = fixture.http.requests(forPath: "/v1/session/otp/check")
        XCTAssertEqual(recorded.count, 1)
        XCTAssertNil(
            recorded.first?.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/otp/check is unauthenticated; DPoP must not be attached"
        )
    }

    /// `/otp` (the verification kick-off) is also unauthenticated.
    /// The current code already omits DPoP there; this test pins
    /// the contract so a future refactor can't reintroduce it.
    func test_startOTPLogin_doesNotAttachDPoPHeader() async throws {
        let fixture = try makeFixture()
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )

        let recorded = fixture.http.requests(forPath: "/v1/session/otp")
        XCTAssertEqual(recorded.count, 1)
        XCTAssertNil(
            recorded.first?.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/otp is unauthenticated; DPoP must not be attached"
        )
    }

    /// `/login/finalize` is where the access + refresh tokens are
    /// minted and bound to the device DPoP key. DPoP **must** be
    /// attached. Pinning the positive side prevents an over-eager
    /// "remove DPoP from the OTP flow" sweep from gutting the
    /// binding.
    func test_finalizeLogin_attachesDPoPHeader() async throws {
        let fixture = try makeFixture()

        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        _ = try await fixture.client.checkOTP("123456")

        let recorded = fixture.http.requests(forPath: "/v1/session/login/finalize")
        XCTAssertEqual(recorded.count, 1)
        XCTAssertNotNil(
            recorded.first?.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/login/finalize must carry the DPoP proof binding the issued tokens to the device key"
        )
    }

    // MARK: - Happy path

    /// End-to-end OTP login round trip. Establishes that
    /// removing DPoP from `/otp/check` didn't break the flow.
    func test_otpLogin_returnsUser_andPersistsRefreshToken() async throws {
        let fixture = try makeFixture()

        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )
        let user = try await fixture.client.checkOTP("123456")

        XCTAssertEqual(user.profile.userID, "user-1")
        XCTAssertEqual(
            try fixture.refreshTokenStore.get(domain: domain)?.refreshToken,
            "refresh-v1"
        )
    }

    // MARK: - Helpers

    private func makeFixture() throws -> Fixture {
        try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
    }
}

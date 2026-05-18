import Foundation
@testable import PreludeAuth
import XCTest

/// DPoP attachment policy for the password-login flow:
///
///   `/login/email/password` is unauthenticated — no DPoP, no
///   Bearer (no session key or token exists yet).
///   `/login/finalize` IS DPoP-signed: it's where the issued
///   tokens are bound to the device key.
///
/// Sibling to `OTPLoginHeadersTests` — the OTP path's policy is
/// pinned there. Keeping a parallel file for the password path
/// means a future "always sign" / "never sign" sweep on either
/// route is caught by the local file rather than relying on the
/// other flow's coverage.
final class PasswordLoginHeadersTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "pwd-headers-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    func test_loginWithPassword_dpopAttachedOnFinalizeOnly_noBearer() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        fixture.http.install(
            path: "/v1/session/login/email/password",
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

        _ = try await fixture.client.loginWithPassword(
            .init(emailAddress: "alice@example.com", password: "correct horse")
        )

        let pwd = fixture.http.requests(forPath: "/v1/session/login/email/password").first
        XCTAssertNil(pwd?.value(forHTTPHeaderField: HTTPHeader.dpop),
                     "/login/email/password is unauthenticated; no DPoP")
        XCTAssertNil(pwd?.value(forHTTPHeaderField: HTTPHeader.authorization),
                     "/login/email/password is unauthenticated; no Bearer")

        let finalize = fixture.http.requests(forPath: "/v1/session/login/finalize").first
        XCTAssertNotNil(finalize?.value(forHTTPHeaderField: HTTPHeader.dpop),
                        "/login/finalize must carry the DPoP proof binding the issued tokens")
        XCTAssertNil(finalize?.value(forHTTPHeaderField: HTTPHeader.authorization),
                     "/login/finalize is challenge-token-authenticated; no Bearer")
    }
}

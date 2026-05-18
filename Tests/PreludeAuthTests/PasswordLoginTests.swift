import Foundation
@testable import PreludeAuth
import XCTest

final class PasswordLoginTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "pwd-login-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    /// Well-formed, unsigned JWT — `JWT.decode` reads the payload only.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    // MARK: - Happy path

    func test_loginWithPassword_returnsUser_andPersistsRefreshToken() async throws {
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

        let user = try await fixture.client.loginWithPassword(
            LoginWithPasswordOptions(
                emailAddress: "alice@example.com",
                password: "correct horse battery staple"
            )
        )

        XCTAssertEqual(user.profile.userID, "user-1")
        XCTAssertEqual(
            try fixture.refreshTokenStore.get(domain: domain)?.refreshToken,
            "refresh-v1"
        )
    }

    // MARK: - Error mapping

    func test_loginWithPassword_invalidPassword_mapsStructured() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/email/password",
            response: .json(
                ["code": "invalid_password", "message": "policy"],
                statusCode: 400
            )
        )

        do {
            _ = try await fixture.client.loginWithPassword(
                .init(emailAddress: "alice@example.com", password: "x")
            )
            XCTFail("expected invalidPassword")
        } catch PreludeAuthError.invalidPassword {
            // expected
        }
    }

    func test_loginWithPassword_badCredentials_mapsUnauthorized() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/email/password",
            response: .json(
                ["code": "unauthorized", "message": "bad credentials"],
                statusCode: 401
            )
        )

        do {
            _ = try await fixture.client.loginWithPassword(
                .init(emailAddress: "alice@example.com", password: "wrong")
            )
            XCTFail("expected unauthorized")
        } catch PreludeAuthError.unauthorized {
            // expected
        }
    }

    func test_loginWithPassword_missingChallengeToken_throwsStructured() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/email/password",
            response: .json([:])
        )

        do {
            _ = try await fixture.client.loginWithPassword(
                .init(emailAddress: "alice@example.com", password: "any")
            )
            XCTFail("expected missingChallengeToken")
        } catch PreludeAuthError.missingChallengeToken {
            // expected
        }
    }

    // MARK: - Race with logout

    func test_loginWithPassword_racedByLogout_doesNotResurrectSession() async throws {
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
        fixture.http.installGate(path: "/v1/session/login/finalize")

        let login = Task {
            try await fixture.client.loginWithPassword(
                .init(emailAddress: "alice@example.com", password: "correct horse")
            )
        }
        try await waitUntil {
            fixture.http.requestCount(forPath: "/v1/session/login/finalize") >= 1
        }

        // Logout lands while /login/finalize is suspended: it bumps
        // the session epoch and wipes the stores.
        try await fixture.client.logout()

        fixture.http.releaseGate(path: "/v1/session/login/finalize")

        do {
            _ = try await login.value
            XCTFail("login should have been invalidated by the racing logout")
        } catch PreludeAuthError.unauthorized {
            // expected
        }

        XCTAssertNil(try fixture.refreshTokenStore.get(domain: domain))
        let cached = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(cached)
    }

    // MARK: - Helpers

    private func waitUntil(
        timeout: TimeInterval = 2,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ condition: @escaping () -> Bool
    ) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if condition() {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out", file: file, line: line)
    }
}

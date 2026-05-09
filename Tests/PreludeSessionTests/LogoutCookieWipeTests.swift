import Foundation
import XCTest
@testable import PreludeSession

/// `HTTPCookieStorage.shared` is persistent across launches.
/// `logout()` must clear cookies scoped to our host so server-set
/// markers like `did` don't outlive the session.
final class LogoutCookieWipeTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        // Unique host per test so HTTPCookieStorage.shared doesn't
        // bleed state across runs.
        domain = "logout-cookie-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        // Belt-and-braces clean-up if a test failed before the wipe.
        for cookie in HTTPCookieStorage.shared.cookies(for: baseURL) ?? [] {
            HTTPCookieStorage.shared.deleteCookie(cookie)
        }
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    func test_logout_clearsHostScopedCookies() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        // Plant the cookies the server would normally set.
        for line in [
            "did=session-abc; Path=/; Secure; HttpOnly",
            "__Host-verification-login_42=challenge; Path=/; Secure; HttpOnly",
        ] {
            for cookie in HTTPCookie.cookies(
                withResponseHeaderFields: ["Set-Cookie": line], for: baseURL
            ) {
                HTTPCookieStorage.shared.setCookie(cookie)
            }
        }
        XCTAssertEqual(
            HTTPCookieStorage.shared.cookies(for: baseURL)?.count, 2,
            "fixture must actually plant cookies before logout"
        )

        try await fixture.client.logout()

        XCTAssertEqual(
            HTTPCookieStorage.shared.cookies(for: baseURL)?.count ?? 0, 0,
            "logout must wipe host-scoped cookies"
        )
    }
}

import Foundation
@testable import PreludeAuth
import XCTest

/// Pins attribute round-trip through Foundation's parser for the
/// two cookies the server sets during login: `did` (host-scoped
/// session marker) and `__Host-verification-login_<id>` (one-shot
/// challenge cookie).
///
/// The SDK doesn't manage cookies itself; this test pins that the
/// parser preserves the attributes server engineers rely on, so
/// the OS-level cookie store sees them with the correct shape.
final class CookieParsingTests: XCTestCase {
    private let url = URL(string: "https://api.example.com/v1/session/otp")!

    // MARK: - did

    func test_didCookie_parsesWithSecureHttpOnlyPathRoot() throws {
        let setCookie = "did=session-abc; Path=/; Secure; HttpOnly; SameSite=Strict"
        let cookie = try parseOne(setCookie)

        XCTAssertEqual(cookie.name, "did")
        XCTAssertEqual(cookie.value, "session-abc")
        XCTAssertEqual(cookie.path, "/")
        XCTAssertTrue(cookie.isSecure)
        XCTAssertTrue(cookie.isHTTPOnly)
        XCTAssertEqual(cookie.domain, "api.example.com",
                       "absent Domain attr → host-scoped to the URL host")
        if #available(iOS 13.0, macOS 10.15, *) {
            XCTAssertEqual(cookie.sameSitePolicy, .sameSiteStrict)
        }
    }

    // MARK: - __Host- prefix

    /// `__Host-` prefix requires Secure + Path=/ + no Domain.
    /// Pin all three on the parsed cookie.
    func test_hostPrefixedCookie_parsesAndIsHostScoped() throws {
        let setCookie = "__Host-verification-login_42=challenge-xyz; "
            + "Path=/; Secure; HttpOnly; SameSite=Lax"
        let cookie = try parseOne(setCookie)

        XCTAssertEqual(cookie.name, "__Host-verification-login_42")
        XCTAssertTrue(cookie.name.hasPrefix("__Host-"))
        XCTAssertEqual(cookie.path, "/")
        XCTAssertTrue(cookie.isSecure)
        XCTAssertTrue(cookie.isHTTPOnly)
        // `__Host-` cookies must not carry a Domain attribute.
        // Foundation defaults `domain` to the URL host when none
        // was sent; pin that the parsed value matches the host
        // exactly (no leading dot, no override).
        XCTAssertEqual(cookie.domain, "api.example.com")
        XCTAssertFalse(cookie.domain.hasPrefix("."))
    }

    /// Negative side: a `__Host-`-named cookie that arrived with
    /// a Domain attribute is malformed per RFC 6265bis. Foundation
    /// will still parse it, but the resulting `domain` reveals
    /// the override — pin so a test catches a server regression
    /// that emits the bad shape.
    func test_hostPrefixedCookie_withDomainAttr_isDetectable() throws {
        let bad = "__Host-verification-login_42=x; "
            + "Path=/; Secure; HttpOnly; Domain=example.com"
        let cookie = try parseOne(bad)
        XCTAssertNotEqual(
            cookie.domain, "api.example.com",
            "Domain attr override is what __Host- forbids — server-side bug"
        )
    }

    // MARK: - Helpers

    private func parseOne(_ line: String) throws -> HTTPCookie {
        let cookies = HTTPCookie.cookies(
            withResponseHeaderFields: ["Set-Cookie": line],
            for: url
        )
        return try XCTUnwrap(cookies.first)
    }
}

import Foundation
@testable import PreludeAuth
import XCTest

/// Pins the contract that bearer secrets — access tokens, refresh
/// tokens, JWT-encoded challenge tokens, passwords, OTP codes —
/// never appear in any printable / loggable surface the SDK
/// exposes.
///
/// The SDK has no `os_log` / `Logger` calls of its own, so the
/// real risk is host apps logging SDK objects or thrown errors.
/// These tests cover both: per-type textual representations
/// (`description`, `debugDescription`, `dump` via `Mirror`), and
/// the error-message paths that previously folded response-body
/// snippets into thrown errors.
final class LoggingHygieneTests: XCTestCase {
    // MARK: - RedactedString (the contract)

    func test_redactedString_textualReps_renderAsRedacted() {
        let secret = RedactedString("hunter2")

        XCTAssertEqual("\(secret)", "<redacted>")
        XCTAssertEqual(String(reflecting: secret), "<redacted>")

        // `dump` walks `Mirror`; verify the override applies.
        var dumpOutput = ""
        dump(secret, to: &dumpOutput)
        XCTAssertFalse(dumpOutput.contains("hunter2"), "dump leaked the secret: \(dumpOutput)")

        // The named unwrap is the only documented escape hatch.
        XCTAssertEqual(secret.value, "hunter2")
    }

    // MARK: - AccessTokenEntry

    func test_accessTokenEntry_textualReps_redactToken() {
        let entry = AccessTokenEntry(accessToken: "eyJ.SECRET.sig", expiresAt: 1_700_000_000)

        let printed = "\(entry)"
        let dbg = String(reflecting: entry)
        var dumped = ""
        dump(entry, to: &dumped)

        for surface in [printed, dbg, dumped] {
            XCTAssertFalse(
                surface.contains("eyJ.SECRET.sig"),
                "AccessTokenEntry leaked the access token: \(surface)"
            )
            XCTAssertTrue(
                surface.contains("redacted"),
                "AccessTokenEntry must declare its token as redacted: \(surface)"
            )
        }
        XCTAssertTrue(printed.contains("1700000000"), "expiresAt should remain visible for debugging")
    }

    // MARK: - RefreshTokenRecord

    func test_refreshTokenRecord_textualReps_redactToken() {
        let record = RefreshTokenRecord(
            refreshToken: "rfr.SECRET.42",
            refreshTokenExpiresAt: "2030-01-01T00:00:00Z"
        )

        let printed = "\(record)"
        let dbg = String(reflecting: record)
        var dumped = ""
        dump(record, to: &dumped)

        for surface in [printed, dbg, dumped] {
            XCTAssertFalse(
                surface.contains("rfr.SECRET.42"),
                "RefreshTokenRecord leaked the refresh token: \(surface)"
            )
            XCTAssertTrue(
                surface.contains("redacted"),
                "RefreshTokenRecord must declare its token as redacted: \(surface)"
            )
        }
    }

    // MARK: - JWT

    func test_jwt_textualReps_redactEncodedToken() throws {
        // Well-formed JWT with payload `{"sub":"user-1","jti":"abc"}`.
        let token =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJqdGkiOiJhYmMifQ.SECRET-SIG"
        let jwt = try JWT.decode(token)

        let printed = "\(jwt)"
        let dbg = String(reflecting: jwt)
        var dumped = ""
        dump(jwt, to: &dumped)

        for surface in [printed, dbg, dumped] {
            XCTAssertFalse(
                surface.contains("SECRET-SIG"),
                "JWT leaked the signature: \(surface)"
            )
            // Encoded payload base64 (the `eyJ...` chunk) is a bearer
            // identifier; pin its absence too.
            XCTAssertFalse(
                surface.contains("eyJzdWIiOiJ1c2VyLTEi"),
                "JWT leaked the encoded payload: \(surface)"
            )
            XCTAssertTrue(
                surface.contains("redacted"),
                "JWT must declare itself as redacted: \(surface)"
            )
        }
    }

    // MARK: - LoginWithPasswordOptions

    /// `description` interpolates `password`, which is a
    /// `RedactedString`. Pin that the interpolation flows through
    /// the redaction.
    func test_loginWithPasswordOptions_description_redactsPassword() {
        let options = LoginWithPasswordOptions(
            emailAddress: "alice@example.com",
            password: "correct horse battery staple"
        )

        let printed = "\(options)"
        XCTAssertFalse(
            printed.contains("correct horse battery staple"),
            "LoginWithPasswordOptions leaked the password: \(printed)"
        )
        XCTAssertTrue(printed.contains("alice@example.com"))
        XCTAssertTrue(printed.contains("redacted"))
    }

    // MARK: - HTTP error messages

    /// Decoding a 2xx body that fails to match the response schema
    /// must NOT fold the body into the error message — credential-
    /// issuing endpoints (`/refresh`, `/login/finalize`,
    /// `/otp/check`) put bearer tokens in successful response
    /// bodies.
    func test_decodingFailure_doesNotIncludeResponseBody() async throws {
        let domain = "logging-test-\(UUID().uuidString.lowercased()).example"
        let baseURL = try XCTUnwrap(URL(string: "https://\(domain)"))
        let clock: NowProvider = { Date(timeIntervalSince1970: 1_000_000) }
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        // 200 OK with a JSON body shaped as an array, not an
        // object. `ChallengeTokenResponse` is a struct, so the
        // decoder rejects this with a `typeMismatch` — exactly the
        // branch we want to exercise. A `{"unexpected_field": …}`
        // body would decode successfully (every modelled field is
        // optional) and short-circuit on `missingChallengeToken`
        // before ever hitting the `decoding_failed` path.
        let bait = "eyJ.LEAK-BAIT.sig"
        let arrayBody = Data("[\"\(bait)\"]".utf8)
        fixture.http.install(
            path: "/v1/session/login/email/password",
            response: StubHTTPSession.CannedResponse(
                statusCode: 200,
                body: arrayBody,
                headers: ["Content-Type": "application/json"]
            )
        )

        do {
            _ = try await fixture.client.loginWithPassword(
                LoginWithPasswordOptions(
                    emailAddress: "alice@example.com",
                    password: "x"
                )
            )
            XCTFail("expected decoding to fail")
        } catch let PreludeAuthError.generic(code, message) {
            XCTAssertEqual(code, "decoding_failed")
            XCTAssertFalse(
                message.contains(bait),
                "decoding error must not surface the response body: \(message)"
            )
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    /// Non-2xx with a body that doesn't decode as `APIErrorJSON`
    /// (e.g. a buffering proxy returning a 5xx that echoes the
    /// original request) must NOT fold the body into the error.
    /// Defense in depth — some proxies bounce the original
    /// payload, which can carry passwords / OTP codes.
    func test_nonAPIErrorResponse_doesNotIncludeResponseBody() async throws {
        let domain = "logging-test-\(UUID().uuidString.lowercased()).example"
        let baseURL = try XCTUnwrap(URL(string: "https://\(domain)"))
        let clock: NowProvider = { Date(timeIntervalSince1970: 1_000_000) }
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        // Stub a 502 with a "the proxy bounced your password back"
        // shaped body. Not parseable as APIErrorJSON.
        let payload = "echoed-password=hunter2"
        let response = StubHTTPSession.CannedResponse(
            statusCode: 502,
            body: Data(payload.utf8),
            headers: ["Content-Type": "text/plain"]
        )
        fixture.http.install(path: "/v1/session/login/email/password", response: response)

        do {
            _ = try await fixture.client.loginWithPassword(
                LoginWithPasswordOptions(
                    emailAddress: "alice@example.com",
                    password: "hunter2"
                )
            )
            XCTFail("expected an error from the 502 response")
        } catch let PreludeAuthError.generic(code, message) {
            XCTAssertEqual(code, "http_502")
            XCTAssertFalse(
                message.contains("hunter2"),
                "non-API-error message must not surface the response body: \(message)"
            )
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }
}

import Foundation
@testable import PreludeAuth
import XCTest

/// Wire bodies that carry plaintext (password / OTP code) must
/// not surface the secret through `description`,
/// `debugDescription`, or `dump()`. The encoded JSON still goes
/// to the network — redaction targets only stringified surfaces.
final class RequestBodyRedactionTests: XCTestCase {
    func test_loginWithPasswordRequestBody_redactsPassword() {
        let body = LoginWithPasswordRequestBody(
            emailAddress: "alice@example.com",
            password: "hunter2",
            dispatchID: "d-1"
        )
        for surface in [
            "\(body)",
            String(reflecting: body),
            dumpToString(body),
        ] {
            XCTAssertFalse(surface.contains("hunter2"), surface)
            XCTAssertTrue(surface.contains("redacted"), surface)
            XCTAssertTrue(surface.contains("alice@example.com"))
        }
    }

    func test_changePasswordRequestBody_redactsPassword() {
        let body = ChangePasswordRequestBody(password: "hunter2")
        for surface in ["\(body)", String(reflecting: body), dumpToString(body)] {
            XCTAssertFalse(surface.contains("hunter2"), surface)
            XCTAssertTrue(surface.contains("redacted"), surface)
        }
    }

    func test_checkOTPRequestBody_redactsCode() {
        let body = CheckOTPRequestBody(code: "123456")
        for surface in ["\(body)", String(reflecting: body), dumpToString(body)] {
            XCTAssertFalse(surface.contains("123456"), surface)
            XCTAssertTrue(surface.contains("redacted"), surface)
        }
    }

    func test_migrateRequestBody_redactsLegacyToken() {
        let body = MigrateRequestBody(
            token: "legacy-bearer",
            codeChallenge: "ch4ll3nge",
            dispatchID: "d-1"
        )
        for surface in ["\(body)", String(reflecting: body), dumpToString(body)] {
            XCTAssertFalse(surface.contains("legacy-bearer"), surface)
            XCTAssertTrue(surface.contains("redacted"), surface)
            XCTAssertTrue(surface.contains("ch4ll3nge"))
        }
    }

    func test_stepUpOTPCheckRequestBody_redactsCodeAndChallenge() {
        let body = StepUpOTPCheckRequestBody(code: "123456", challengeToken: "challenge-bait")
        for surface in ["\(body)", String(reflecting: body), dumpToString(body)] {
            XCTAssertFalse(surface.contains("123456"), surface)
            XCTAssertFalse(surface.contains("challenge-bait"), surface)
            XCTAssertTrue(surface.contains("redacted"), surface)
        }
    }

    private func dumpToString(_ value: some Any) -> String {
        var out = ""; dump(value, to: &out); return out
    }
}

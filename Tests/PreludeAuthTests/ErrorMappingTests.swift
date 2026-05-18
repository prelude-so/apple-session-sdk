@testable import PreludeAuth
import XCTest

/// Wire `code` → typed ``PreludeAuthError`` mapping. Covers
/// the codes the backend actually emits today; unrecognised codes
/// must round-trip through ``PreludeAuthError/generic(code:message:)``
/// so callers retain a useful debug signal.
final class ErrorMappingTests: XCTestCase {
    private func map(_ code: String, message: String = "boom") -> PreludeAuthError {
        PreludeAuthError.from(apiError: APIErrorJSON(
            code: code,
            message: message,
            type: nil,
            requestId: nil
        ))
    }

    func test_internal_mapsToInternalServerError() {
        // Backend's 500 code is `internal`. The legacy spelling
        // `internal_server_error` keeps callers on older builds
        // working.
        guard case .internalServerError = map("internal") else {
            XCTFail("`internal` must map to .internalServerError")
            return
        }
        guard case .internalServerError = map("internal_server_error") else {
            XCTFail("`internal_server_error` must map to .internalServerError")
            return
        }
    }

    func test_expiredAndReusedChallengeTokens_areTyped() {
        guard case .expiredChallengeToken = map("expired_challenge_token") else {
            XCTFail("expired_challenge_token must surface as a typed case")
            return
        }
        guard case .tokenReused = map("token_reused") else {
            XCTFail("token_reused must surface as a typed case")
            return
        }
    }

    func test_dpopAndUnauthorizedFamily_collapsesToUnauthorized() {
        for code in [
            "unauthorized",
            "invalid_dpop_proof",
            "dpop_key_mismatch",
            "missing_dpop_proof",
            "use_dpop_nonce",
        ] {
            guard case .unauthorized = map(code) else {
                XCTFail("\(code) must map to .unauthorized")
                return
            }
        }
    }

    func test_badRequestFamily_collapsesToBadRequest() {
        for code in [
            "bad_request",
            "invalid_identifier",
            "invalid_metadata",
            "invalid_pagination_limit",
            "invalid_pagination_offset",
            "invalid_redirect_uri",
            "invalid_verification_token",
            "oauth_provider_not_configured",
            "oauth_provider_disabled",
            "email_domain_not_verified",
            "insufficient_balance",
        ] {
            guard case .badRequest = map(code) else {
                XCTFail("\(code) must map to .badRequest")
                return
            }
        }
    }

    func test_stepUpStateMachineErrors_collapseToInvalidChallengeToken() {
        let codes = [
            "invalid_challenge_token",
            "step_not_completed",
            "step_not_found",
            "step_bypassed",
            "token_mismatch",
        ]
        for code in codes {
            guard case .invalidChallengeToken = map(code) else {
                XCTFail("\(code) must map to .invalidChallengeToken")
                return
            }
        }
    }

    func test_forbiddenFamily_includesScopeAndConfig() {
        let codes = [
            "forbidden",
            "auth_blocked",
            "scope_not_allowed",
            "not_configured",
            "direct_scope_identifier_mismatch",
            "invalid_verify_configuration",
            "suspended_account",
            "invalid_api_key",
            "email_verification_not_allowed",
        ]
        for code in codes {
            guard case .forbidden = map(code) else {
                XCTFail("\(code) must map to .forbidden")
                return
            }
        }
    }

    func test_resourceState_isTyped() {
        guard case .notFound = map("not_found") else {
            XCTFail("not_found must map to .notFound")
            return
        }
        for code in ["conflict", "identifier_already_exists"] {
            guard case .conflict = map(code) else {
                XCTFail("\(code) must map to .conflict")
                return
            }
        }
    }

    func test_unknownCode_roundTripsThroughGeneric() {
        let err = map("totally_made_up_code", message: "hi")
        guard case let .generic(code, message) = err else {
            XCTFail("Unknown codes must surface as .generic")
            return
        }
        XCTAssertEqual(code, "totally_made_up_code")
        XCTAssertEqual(message, "hi")
    }
}

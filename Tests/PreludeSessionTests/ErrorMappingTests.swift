import XCTest
@testable import PreludeSession

/// Wire `code` → typed ``PreludeSessionError`` mapping. Covers
/// the codes the backend actually emits today; unrecognised codes
/// must round-trip through ``PreludeSessionError/generic(code:message:)``
/// so callers retain a useful debug signal.
final class ErrorMappingTests: XCTestCase {
    private func map(_ code: String, message: String = "boom") -> PreludeSessionError {
        PreludeSessionError.from(apiError: APIErrorJSON(
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
            return XCTFail("`internal` must map to .internalServerError")
        }
        guard case .internalServerError = map("internal_server_error") else {
            return XCTFail("`internal_server_error` must map to .internalServerError")
        }
    }

    func test_expiredAndReusedChallengeTokens_areTyped() {
        guard case .expiredChallengeToken = map("expired_challenge_token") else {
            return XCTFail("expired_challenge_token must surface as a typed case")
        }
        guard case .tokenReused = map("token_reused") else {
            return XCTFail("token_reused must surface as a typed case")
        }
    }

    func test_dpopAndUnauthorizedFamily_collapsesToUnauthorized() {
        for code in ["unauthorized", "invalid_dpop_proof", "dpop_key_mismatch", "missing_dpop_proof"] {
            guard case .unauthorized = map(code) else {
                return XCTFail("\(code) must map to .unauthorized")
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
        ] {
            guard case .badRequest = map(code) else {
                return XCTFail("\(code) must map to .badRequest")
            }
        }
    }

    func test_stepUpStateMachineErrors_collapseToInvalidChallengeToken() {
        for code in ["invalid_challenge_token", "step_not_completed", "step_not_found", "step_bypassed", "token_mismatch"] {
            guard case .invalidChallengeToken = map(code) else {
                return XCTFail("\(code) must map to .invalidChallengeToken")
            }
        }
    }

    func test_forbiddenFamily_includesScopeAndConfig() {
        for code in ["forbidden", "auth_blocked", "scope_not_allowed", "not_configured", "direct_scope_identifier_mismatch"] {
            guard case .forbidden = map(code) else {
                return XCTFail("\(code) must map to .forbidden")
            }
        }
    }

    func test_resourceState_isTyped() {
        guard case .notFound = map("not_found") else {
            return XCTFail("not_found must map to .notFound")
        }
        for code in ["conflict", "identifier_already_exists"] {
            guard case .conflict = map(code) else {
                return XCTFail("\(code) must map to .conflict")
            }
        }
    }

    func test_unknownCode_roundTripsThroughGeneric() {
        let err = map("totally_made_up_code", message: "hi")
        guard case let .generic(code, message) = err else {
            return XCTFail("Unknown codes must surface as .generic")
        }
        XCTAssertEqual(code, "totally_made_up_code")
        XCTAssertEqual(message, "hi")
    }
}

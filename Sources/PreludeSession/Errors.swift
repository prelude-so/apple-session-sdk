import Foundation

/// Errors thrown by ``PreludeSessionClient``.
///
/// Wire-protocol errors from the server are mapped to typed
/// cases (`unauthorized`, `invalidPassword`, `insufficientScope`,
/// `expiredChallengeToken`, …); the associated `String` carries
/// the server's display message. Transport failures surface as
/// ``network(underlying:)`` or ``timeout``. Codes the SDK
/// doesn't recognise round-trip through ``generic(code:message:)``.
public enum PreludeSessionError: Error, Sendable {
    case badRequest(String)
    case unauthorized(String)
    case rateLimited(String)
    case internalServerError(String)
    /// Server response lacked an expected challenge token.
    case missingChallengeToken(String)
    /// Backend-issued challenge token is invalid or its step-up
    /// state machine cannot progress (e.g. step skipped or not
    /// completed). Recover via ``requestStepUp(scope:)``.
    case invalidChallengeToken(String)
    /// Challenge token expired before it was redeemed. Recover
    /// via ``requestStepUp(scope:)``.
    case expiredChallengeToken(String)
    /// Single-use token was replayed. Surfaces from `/login/finalize`,
    /// `/otp/check`, and `/stepup/continue` on a 409.
    case tokenReused(String)
    /// OTP code submitted during login was wrong or expired. Distinct
    /// from ``unauthorized``: retry the code, don't re-login.
    case invalidOTPCode(String)
    /// The current session could not be refreshed.
    case refreshFailed(String)
    case timeout
    case invalidConfiguration(String)
    /// Password rejected by the server's policy. Distinct from
    /// ``unauthorized(_:)`` ("wrong password").
    case invalidPassword(String)
    /// Caller is authenticated but policy denies this action.
    case forbidden(String)
    /// Access token lacks a scope the endpoint requires. Recover via
    /// ``requestStepUp(scope:)``.
    case insufficientScope(String)
    /// Resource the request referenced does not exist.
    case notFound(String)
    /// Resource state conflicts with the request (e.g. duplicate
    /// identifier on sign-up).
    case conflict(String)
    case network(underlying: Error)
    /// Error code not recognised by the SDK.
    case generic(code: String, message: String)
}

extension PreludeSessionError {
    static func from(apiError: APIErrorJSON) -> PreludeSessionError {
        let message = apiError.displayMessage
        switch apiError.code {
        case "bad_request",
             "invalid_identifier",
             "invalid_metadata",
             "invalid_pagination_limit",
             "invalid_pagination_offset",
             "invalid_redirect_uri",
             "invalid_verification_token",
             "oauth_provider_not_configured",
             "oauth_provider_disabled":
            return .badRequest(message)
        case "unauthorized",
             "invalid_dpop_proof",
             "dpop_key_mismatch",
             "missing_dpop_proof":
            return .unauthorized(message)
        case "bad_check_code":
            return .invalidOTPCode(message)
        case "rate_limited", "too_many_requests":
            return .rateLimited(message)
        case "internal", "internal_server_error":
            return .internalServerError(message)
        case "missing_challenge_token":
            return .missingChallengeToken(message)
        case "invalid_challenge_token",
             "step_not_completed",
             "step_not_found",
             "step_bypassed",
             "token_mismatch":
            return .invalidChallengeToken(message)
        case "expired_challenge_token":
            return .expiredChallengeToken(message)
        case "token_reused":
            return .tokenReused(message)
        case "invalid_password":
            return .invalidPassword(message)
        case "forbidden",
             "auth_blocked",
             "scope_not_allowed",
             "not_configured",
             "direct_scope_identifier_mismatch":
            return .forbidden(message)
        case "insufficient_scope":
            return .insufficientScope(message)
        case "not_found":
            return .notFound(message)
        case "conflict", "identifier_already_exists":
            return .conflict(message)
        default:
            return .generic(code: apiError.code, message: message)
        }
    }
}

extension PreludeSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .badRequest(message):
            return "BadRequest: \(message)"
        case let .unauthorized(message):
            return "Unauthorized: \(message)"
        case let .rateLimited(message):
            return "RateLimited: \(message)"
        case let .internalServerError(message):
            return "InternalServerError: \(message)"
        case let .missingChallengeToken(message):
            return "MissingChallengeToken: \(message)"
        case let .invalidChallengeToken(message):
            return "InvalidChallengeToken: \(message)"
        case let .expiredChallengeToken(message):
            return "ExpiredChallengeToken: \(message)"
        case let .tokenReused(message):
            return "TokenReused: \(message)"
        case let .invalidOTPCode(message):
            return "InvalidOTPCode: \(message)"
        case let .refreshFailed(message):
            return "RefreshFailed: \(message)"
        case .timeout:
            return "Timeout"
        case let .invalidConfiguration(message):
            return "InvalidConfiguration: \(message)"
        case let .invalidPassword(message):
            return "InvalidPassword: \(message)"
        case let .forbidden(message):
            return "Forbidden: \(message)"
        case let .insufficientScope(message):
            return "InsufficientScope: \(message)"
        case let .notFound(message):
            return "NotFound: \(message)"
        case let .conflict(message):
            return "Conflict: \(message)"
        case let .network(underlying):
            return "Network: \(underlying.localizedDescription)"
        case let .generic(code, message):
            return "\(code): \(message)"
        }
    }
}

extension PreludeSessionError: CustomStringConvertible {
    public var description: String {
        errorDescription ?? "Unknown session error"
    }
}

import Foundation

/// Errors thrown by ``PreludeSessionClient``.
///
/// Wire-protocol errors from the server are mapped to typed
/// cases (`unauthorized`, `invalidPassword`, `insufficientScope`,
/// `forbidden`, `rateLimited`, `internalServerError`, …); the
/// associated `String` carries the server's display message.
/// Transport failures surface as ``network(underlying:)`` or
/// ``timeout``. Codes the SDK doesn't recognise round-trip
/// through ``generic(code:message:)``.
public enum PreludeSessionError: Error, Sendable {
    case badRequest(String)
    case unauthorized(String)
    case rateLimited(String)
    case internalServerError(String)
    /// Server response lacked an expected challenge token.
    case missingChallengeToken(String)
    /// Backend-issued challenge token is invalid.
    case invalidChallengeToken(String)
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
    case network(underlying: Error)
    /// Error code not recognised by the SDK.
    case generic(code: String, message: String)
}

extension PreludeSessionError {
    static func from(apiError: APIErrorJSON) -> PreludeSessionError {
        let message = apiError.displayMessage
        switch apiError.code {
        case "bad_request":
            return .badRequest(message)
        case "unauthorized":
            return .unauthorized(message)
        case "bad_check_code":
            return .invalidOTPCode(message)
        case "rate_limited", "too_many_requests":
            return .rateLimited(message)
        case "internal_server_error":
            return .internalServerError(message)
        case "missing_challenge_token":
            return .missingChallengeToken(message)
        case "invalid_challenge_token":
            return .invalidChallengeToken(message)
        case "invalid_password":
            return .invalidPassword(message)
        case "forbidden", "auth_blocked", "scope_not_allowed":
            return .forbidden(message)
        case "insufficient_scope":
            return .insufficientScope(message)
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

import Foundation

/// Wall-clock source. Tests inject a fixed value.
typealias NowProvider = @Sendable () -> Date

let defaultNowProvider: NowProvider = { Date() }

// MARK: - Public types

/// A JSON value as carried by a decoded JWT payload. Integer and
/// floating-point numbers are kept separate so large integer ids
/// (e.g. 64-bit `sub` claims) keep their precision instead of
/// rounding through `Double`.
public enum PreludeJSONValue: Sendable, Equatable {
    case string(String)
    case int(Int64)
    case double(Double)
    case bool(Bool)
    case array([PreludeJSONValue])
    case object([String: PreludeJSONValue])
    case null
}

extension PreludeJSONValue: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let bool = try? container.decode(Bool.self) {
            // Bool first so true/false aren't coerced to 1/0.
            self = .bool(bool)
        } else if let int = try? container.decode(Int64.self) {
            self = .int(int)
        } else if let double = try? container.decode(Double.self) {
            self = .double(double)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let array = try? container.decode([PreludeJSONValue].self) {
            self = .array(array)
        } else if let object = try? container.decode([String: PreludeJSONValue].self) {
            self = .object(object)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported JSON value"
            )
        }
    }
}

/// Identifier type used to start a login flow.
public enum PreludeIdentifierType: String, Codable, Sendable {
    case phoneNumber = "phone_number"
    case emailAddress = "email_address"
}

/// A user identifier (phone number or email address).
public struct PreludeIdentifier: Codable, Sendable, Equatable {
    public var type: PreludeIdentifierType
    public var value: String

    public init(type: PreludeIdentifierType, value: String) {
        self.type = type
        self.value = value
    }
}

/// A decoded user profile, sourced from the current access token's claims.
public struct PreludeProfile: Sendable, Equatable {
    /// Stable user identifier. Sourced from the JWT `sub` claim.
    public var userID: String?
    /// Session identifier. Sourced from the JWT `sid` claim.
    public var sessionID: String?
    /// All other top-level claims, with JSON shape preserved.
    public var extras: [String: PreludeJSONValue]

    public init(
        userID: String? = nil,
        sessionID: String? = nil,
        extras: [String: PreludeJSONValue] = [:]
    ) {
        self.userID = userID
        self.sessionID = sessionID
        self.extras = extras
    }
}

/// The authenticated user returned from login and refresh flows.
public struct PreludeUser: Sendable, Equatable {
    public var accessToken: String
    public var profile: PreludeProfile

    public init(accessToken: String, profile: PreludeProfile) {
        self.accessToken = accessToken
        self.profile = profile
    }
}

/// Options for starting an OTP login.
public struct StartOTPLoginOptions: Codable, Sendable {
    public var identifier: PreludeIdentifier

    /// Identifier of a server-side login configuration that
    /// overrides the default OTP delivery rules.
    public var loginConfigID: String?

    enum CodingKeys: String, CodingKey {
        case identifier
        case loginConfigID = "login_config_id"
    }

    public init(identifier: PreludeIdentifier, loginConfigID: String? = nil) {
        self.identifier = identifier
        self.loginConfigID = loginConfigID
    }
}

// MARK: - Internal wire types

struct StartOTPLoginRequestBody: Encodable {
    var identifier: PreludeIdentifier
    var loginConfigID: String?
    var dispatchID: String?

    enum CodingKeys: String, CodingKey {
        case identifier
        case loginConfigID = "login_config_id"
        case dispatchID = "dispatch_id"
    }
}

struct CheckOTPRequestBody: Encodable {
    var code: String
}

/// Body returned by credential-exchange endpoints that hand back a
/// short-lived, single-use challenge token. Optional so we can
/// surface a structured ``PreludeSessionError/missingChallengeToken(_:)``
/// rather than a generic decode error.
struct ChallengeTokenResponse: Decodable {
    var challengeToken: String?

    enum CodingKeys: String, CodingKey {
        case challengeToken = "challenge_token"
    }
}

struct FinalizeLoginRequestBody: Encodable {
    var challengeToken: String

    enum CodingKeys: String, CodingKey {
        case challengeToken = "challenge_token"
    }
}

/// Body returned by `POST /refresh`. The rotated refresh token (when
/// present) arrives via the `X-Refresh-Token` response header.
struct RefreshTokenResponse: Decodable {
    var accessToken: String
    var expiresAt: Int

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case expiresAt = "expires_at"
    }
}

/// A `String` wrapper whose textual representations render as
/// `<redacted>`. Use for secrets that must not appear in logs,
/// errors, `print`, or `po` / `dump` output. Callers reach the
/// raw value via ``value`` — an explicit, named unwrap.
///
/// Not `Codable` by design: wire types that need to send the
/// secret encode ``value`` explicitly.
public struct RedactedString: Sendable {
    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}

extension RedactedString: CustomStringConvertible {
    public var description: String { "<redacted>" }
}

extension RedactedString: CustomDebugStringConvertible {
    public var debugDescription: String { "<redacted>" }
}

// `dump()` walks `Mirror` and would otherwise enumerate stored
// properties; override `customMirror` so reflection also shows
// `<redacted>`.
extension RedactedString: CustomReflectable {
    public var customMirror: Mirror {
        Mirror(reflecting: "<redacted>")
    }
}

/// Options for ``PreludeSessionClient/loginWithPassword(_:)``.
/// The password is wrapped in ``RedactedString`` so the struct
/// is safe to `print` / `dump` / log.
public struct LoginWithPasswordOptions: Sendable {
    public var emailAddress: String

    /// Held only for the duration of one
    /// ``PreludeSessionClient/loginWithPassword(_:)`` call;
    /// never persisted by the SDK.
    public var password: RedactedString

    public init(emailAddress: String, password: String) {
        self.emailAddress = emailAddress
        self.password = RedactedString(password)
    }
}

extension LoginWithPasswordOptions: CustomStringConvertible {
    public var description: String {
        "LoginWithPasswordOptions(emailAddress: \(emailAddress), password: \(password))"
    }
}

/// `Encodable` only — the password never round-trips through a decoder.
struct LoginWithPasswordRequestBody: Encodable {
    var emailAddress: String
    var password: String
    var dispatchID: String?

    enum CodingKeys: String, CodingKey {
        case emailAddress = "identifier"
        case password
        case dispatchID = "dispatch_id"
    }
}

/// The server's configured password compliancy rules.
///
/// Each numeric field is a minimum count. ``maxLength`` of `0` means
/// "no upper bound".
public struct PreludePasswordCompliancy: Sendable, Equatable, Decodable {
    public var minLength: Int
    public var maxLength: Int
    public var uppercase: Int
    public var lowercase: Int
    public var numbers: Int
    public var symbols: Int

    enum CodingKeys: String, CodingKey {
        case minLength = "min_length"
        case maxLength = "max_length"
        case uppercase
        case lowercase
        case numbers
        case symbols
    }

    public init(
        minLength: Int,
        maxLength: Int,
        uppercase: Int,
        lowercase: Int,
        numbers: Int,
        symbols: Int
    ) {
        self.minLength = minLength
        self.maxLength = maxLength
        self.uppercase = uppercase
        self.lowercase = lowercase
        self.numbers = numbers
        self.symbols = symbols
    }
}

/// One rule's outcome from running a password through the server's
/// configured compliancy rules.
public struct PreludePasswordCompliancyResult: Sendable, Equatable {
    public var criterion: PreludePasswordCompliancyCriterion
    /// Observed count in the candidate password.
    public var actual: Int
    /// Required count from the server's configuration.
    public var expected: Int
    public var valid: Bool

    public init(
        criterion: PreludePasswordCompliancyCriterion,
        actual: Int,
        expected: Int,
        valid: Bool
    ) {
        self.criterion = criterion
        self.actual = actual
        self.expected = expected
        self.valid = valid
    }
}

public enum PreludePasswordCompliancyCriterion: String, Sendable, Hashable {
    case minLength = "min_length"
    case maxLength = "max_length"
    case uppercase
    case lowercase
    case numbers
    case symbols
}

/// Aggregate outcome of running a password through the server's
/// compliancy rules. ``valid`` is `true` when every result is valid.
public struct PreludePasswordCompliancyResults: Sendable, Equatable {
    public var valid: Bool
    public var results: [PreludePasswordCompliancyResult]

    public init(valid: Bool, results: [PreludePasswordCompliancyResult]) {
        self.valid = valid
        self.results = results
    }
}

// MARK: - Step-up

/// Status of a step-up flow as reported by the server.
public enum StepUpStatus: String, Sendable, Decodable {
    /// Challenge issued; complete it (typically via
    /// ``PreludeSessionClient/submitStepUpOTP(_:code:)``)
    /// to be granted the scope.
    case `continue` = "continue"

    /// Server is reviewing the request asynchronously. The
    /// caller has nothing to do; poll or surface UI as needed.
    case underReview = "review"

    /// Server refused to grant the scope.
    case blocked = "block"
}

/// Handle returned by ``PreludeSessionClient/requestStepUp(scope:)``
/// and ``PreludeSessionClient/submitStepUpOTP(_:code:)``.
///
/// Value-typed: each caller holds its own challenge, so concurrent
/// step-up flows on a single client don't share state. The wire
/// challenge token and its expiry are deliberately internal — the
/// SDK reads them when you pass the challenge back in.
public struct StepUpChallenge: Sendable, Equatable {
    public let status: StepUpStatus

    /// Server-side identifier for this challenge attempt.
    public let challengeID: String

    /// Next server step (e.g. `"verify_email"`, `"verify_sms"`,
    /// `"completed"`). `nil` when blocked.
    public let currentStep: String?

    /// Scope passed to ``PreludeSessionClient/requestStepUp(scope:)``.
    public let requestedScope: String

    /// Server-issued challenge JWT. Used as the next call's
    /// `challenge_token` and as the DPoP-binding `jti`.
    let token: String

    /// Clock-skew-adjusted absolute expiry, Unix seconds. `0`
    /// for blocked challenges.
    let expiresAt: Int

    init(
        status: StepUpStatus,
        challengeID: String,
        currentStep: String?,
        requestedScope: String,
        token: String,
        expiresAt: Int
    ) {
        self.status = status
        self.challengeID = challengeID
        self.currentStep = currentStep
        self.requestedScope = requestedScope
        self.token = token
        self.expiresAt = expiresAt
    }

    /// Blocked-response factory. Carries no token and is not
    /// submittable.
    static func blocked(requestedScope: String) -> StepUpChallenge {
        StepUpChallenge(
            status: .blocked,
            challengeID: "",
            currentStep: nil,
            requestedScope: requestedScope,
            token: "",
            expiresAt: 0
        )
    }
}

// MARK: - Internal wire types (step-up)

struct StepUpRequestBody: Encodable {
    var scope: String
    var dispatchID: String?

    enum CodingKeys: String, CodingKey {
        case scope
        case dispatchID = "dispatch_id"
    }
}

/// Response from `POST /stepup/request`. `challenge_token` is
/// optional so a `status == .block` response still parses.
struct StepUpRequestResponse: Decodable {
    var status: StepUpStatus
    var challengeToken: String?

    enum CodingKeys: String, CodingKey {
        case status
        case challengeToken = "challenge_token"
    }
}

struct StepUpOTPCreateRequestBody: Encodable {
    var challengeToken: String
    var dispatchID: String?

    enum CodingKeys: String, CodingKey {
        case challengeToken = "challenge_token"
        case dispatchID = "dispatch_id"
    }
}

struct StepUpOTPCheckRequestBody: Encodable {
    var code: String
    var challengeToken: String

    enum CodingKeys: String, CodingKey {
        case code
        case challengeToken = "challenge_token"
    }
}

/// Body for `POST /refresh` after a step-up completes — the server
/// mints an access token carrying the granted scope.
struct StepUpRefreshRequestBody: Encodable {
    var stepUpToken: String

    enum CodingKeys: String, CodingKey {
        case stepUpToken = "step_up_token"
    }
}

// MARK: - Change password

struct ChangePasswordRequestBody: Encodable {
    var password: String
}

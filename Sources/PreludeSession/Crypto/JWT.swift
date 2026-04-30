import Foundation

/// A decoded JSON Web Token. The SDK never verifies tokens locally
/// — the backend is the source of truth.
struct JWT {
    var claims: JWTClaims
    /// Raw decoded payload bytes, for extracting claims not modelled
    /// in ``JWTClaims``.
    var payloadJSON: Data
    /// Base64URL-encoded parts, for re-sending the token verbatim.
    var encoded: EncodedJWT

    struct EncodedJWT {
        var header: String
        var payload: String
        var signature: String
    }
}

/// Standard-claim view. Fields are optional because token shapes
/// vary (challenge vs. access vs. refresh).
struct JWTClaims: Sendable, Equatable {
    var iss: String?
    var sub: String?
    var exp: Int?
    var nbf: Int?
    var iat: Int?
    var jti: String?
    var sid: String?
}

extension JWT {
    /// Decode a compact-serialized JWT. Strict on structure, lenient
    /// on claims.
    static func decode(_ token: String) throws -> JWT {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw PreludeSessionError.invalidChallengeToken("JWT must have three parts")
        }

        let headerPart = String(parts[0])
        let payloadPart = String(parts[1])
        let signaturePart = String(parts[2])

        guard !headerPart.isEmpty, !payloadPart.isEmpty, !signaturePart.isEmpty else {
            throw PreludeSessionError.invalidChallengeToken("JWT has empty parts")
        }

        guard let payloadData = Data.fromBase64URL(payloadPart) else {
            throw PreludeSessionError.invalidChallengeToken("JWT payload is not valid Base64URL")
        }

        let claims: JWTClaims
        do {
            claims = try JSONDecoder().decode(JWTClaims.self, from: payloadData)
        } catch {
            throw PreludeSessionError.invalidChallengeToken(
                "JWT payload is not valid JSON: \(error.localizedDescription)"
            )
        }

        return JWT(
            claims: claims,
            payloadJSON: payloadData,
            encoded: EncodedJWT(
                header: headerPart,
                payload: payloadPart,
                signature: signaturePart
            )
        )
    }
}

extension JWTClaims: Decodable {
    enum CodingKeys: String, CodingKey {
        case iss, sub, exp, nbf, iat, jti, sid
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        iss = try? container.decodeIfPresent(String.self, forKey: .iss)
        sub = try? container.decodeIfPresent(String.self, forKey: .sub)
        exp = try? container.decodeIfPresent(Int.self, forKey: .exp)
        nbf = try? container.decodeIfPresent(Int.self, forKey: .nbf)
        iat = try? container.decodeIfPresent(Int.self, forKey: .iat)
        jti = try? container.decodeIfPresent(String.self, forKey: .jti)
        sid = try? container.decodeIfPresent(String.self, forKey: .sid)
    }
}

extension PreludeProfile {
    /// Build a ``PreludeProfile`` from a decoded JWT. The `sub` and
    /// `sid` claims become typed fields; everything else lands in
    /// ``extras``.
    static func from(jwt: JWT) -> PreludeProfile {
        var extras =
            (try? JSONDecoder().decode([String: PreludeJSONValue].self, from: jwt.payloadJSON)) ?? [:]
        extras.removeValue(forKey: "sub")
        extras.removeValue(forKey: "sid")
        return PreludeProfile(
            userID: jwt.claims.sub,
            sessionID: jwt.claims.sid,
            extras: extras
        )
    }
}

// MARK: - Redacted printing

// Internal type, but defense in depth: every textual representation
// renders as `<JWT redacted>` so a stray `print(jwt)` / `dump(jwt)`
// can't surface the encoded token (which is a bearer secret).
extension JWT: CustomStringConvertible {
    var description: String { "<JWT redacted>" }
}

extension JWT: CustomDebugStringConvertible {
    var debugDescription: String { "<JWT redacted>" }
}

extension JWT: CustomReflectable {
    var customMirror: Mirror { Mirror(reflecting: "<JWT redacted>") }
}

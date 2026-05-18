@testable import PreludeAuth
import XCTest

/// ``PreludeProfile/from(jwt:)``: `sub` and `sid` surface as typed
/// fields and don't appear in `extras`; every other top-level claim
/// lands in `extras` with its JSON type intact.
final class ProfileExtrasTests: XCTestCase {
    // MARK: - Typed fields

    func testTypedFieldsAreSurfacedFromClaims() throws {
        let jwt = try makeJWT([
            "sub": "user_123",
            "sid": "sess_abc",
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertEqual(profile.userID, "user_123")
        XCTAssertEqual(profile.sessionID, "sess_abc")
    }

    func testSubAndSidAreNotDuplicatedIntoExtras() throws {
        let jwt = try makeJWT([
            "sub": "user_123",
            "sid": "sess_abc",
            "email": "user@example.com",
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertNil(profile.extras["sub"])
        XCTAssertNil(profile.extras["sid"])
        XCTAssertEqual(profile.extras["email"], .string("user@example.com"))
    }

    // MARK: - Standard JWT claims

    func testStandardClaimsNotModeledAsTypedFieldsAppearInExtras() throws {
        let jwt = try makeJWT([
            "sub": "user_123",
            "sid": "sess_abc",
            "iss": "https://api.prelude.dev",
            "exp": 1_800_000_000,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "jti": "tok_xyz",
            "aud": "client_42",
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertEqual(profile.extras["iss"], .string("https://api.prelude.dev"))
        XCTAssertEqual(profile.extras["exp"], .int(1_800_000_000))
        XCTAssertEqual(profile.extras["iat"], .int(1_700_000_000))
        XCTAssertEqual(profile.extras["nbf"], .int(1_700_000_000))
        XCTAssertEqual(profile.extras["jti"], .string("tok_xyz"))
        XCTAssertEqual(profile.extras["aud"], .string("client_42"))
    }

    // MARK: - JSON type fidelity

    func testCustomClaimTypesArePreserved() throws {
        let jwt = try makeJWT([
            "sub": "user_123",
            "email": "user@example.com",
            "email_verified": true,
            "account_balance": 199.95,
            "user_id": 9_007_199_254_740_993, // above Double's safe-int threshold
            "roles": ["admin", "billing"],
            "profile": [
                "first_name": "Ada",
                "last_name": "Lovelace",
            ],
            "middle_name": NSNull(),
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertEqual(profile.extras["email"], .string("user@example.com"))
        XCTAssertEqual(profile.extras["email_verified"], .bool(true))
        XCTAssertEqual(profile.extras["account_balance"], .double(199.95))
        XCTAssertEqual(profile.extras["user_id"], .int(9_007_199_254_740_993))
        XCTAssertEqual(profile.extras["roles"], .array([.string("admin"), .string("billing")]))
        XCTAssertEqual(
            profile.extras["profile"],
            .object([
                "first_name": .string("Ada"),
                "last_name": .string("Lovelace"),
            ])
        )
        XCTAssertEqual(profile.extras["middle_name"], .null)
    }

    func testBooleansAreNotCoercedIntoNumbers() throws {
        let jwt = try makeJWT([
            "flag_true": true,
            "flag_false": false,
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertEqual(profile.extras["flag_true"], .bool(true))
        XCTAssertEqual(profile.extras["flag_false"], .bool(false))
    }

    func testUnicodeStringsAreRoundTripped() throws {
        let jwt = try makeJWT([
            "display_name": "Æsop 文字 🎉",
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertEqual(profile.extras["display_name"], .string("Æsop 文字 🎉"))
    }

    // MARK: - Degenerate payloads

    func testEmptyPayloadProducesEmptyProfile() throws {
        let jwt = try makeJWT([:])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertNil(profile.userID)
        XCTAssertNil(profile.sessionID)
        XCTAssertTrue(profile.extras.isEmpty)
    }

    func testMissingSessionIDStillExposesUserID() throws {
        let jwt = try makeJWT([
            "sub": "user_123",
            "email": "user@example.com",
        ])

        let profile = PreludeProfile.from(jwt: jwt)

        XCTAssertEqual(profile.userID, "user_123")
        XCTAssertNil(profile.sessionID)
        XCTAssertEqual(profile.extras["email"], .string("user@example.com"))
    }

    // MARK: - Helpers

    /// Build an unsigned JWT (`header.payload.signature` with a
    /// dummy non-empty signature). The SDK never verifies signatures
    /// locally.
    private func makeJWT(_ claims: [String: Any]) throws -> JWT {
        let header: [String: Any] = ["alg": "RS256", "typ": "JWT"]
        let headerData = try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys])
        let payloadData = try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys])
        let token = [
            headerData.base64URLEncodedString(),
            payloadData.base64URLEncodedString(),
            Data("sig".utf8).base64URLEncodedString(),
        ].joined(separator: ".")
        return try JWT.decode(token)
    }
}

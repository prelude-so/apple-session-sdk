import Foundation
@testable import PreludeAuth

/// Test-side helpers shared between StepUp* test files. Kept
/// separate so each test file stays under the size cap.
enum StepUpFixtures {
    /// Build a well-formed but unsigned JWT — `JWT.decode`
    /// reads header + payload only.
    static func makeChallengeToken(_ claims: [String: Any]) -> String {
        let header = Data(#"{"alg":"HS256","typ":"JWT"}"#.utf8).base64URLEncodedString()
        let payloadData: Data
        do {
            payloadData = try JSONSerialization.data(
                withJSONObject: claims, options: [.sortedKeys]
            )
        } catch {
            preconditionFailure("Invalid JWT claims in test fixture: \(error)")
        }
        let payload = payloadData.base64URLEncodedString()
        return "\(header).\(payload).sig"
    }

    /// Decode a JWT's payload (middle segment) into a claims map.
    static func decodeJWTPayload(_ jwt: String) throws -> [String: Any] {
        let parts = jwt.split(separator: ".")
        guard parts.count == 3, let data = Data.fromBase64URL(String(parts[1])) else {
            throw NSError(domain: "test.fixtures", code: 0)
        }
        return try (JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }
}

import Foundation

extension Data {
    /// Decode a Base64URL-encoded string (RFC 4648 §5).
    static func fromBase64URL(_ string: String) -> Data? {
        var normalized = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddingLength = (4 - normalized.count % 4) % 4
        normalized += String(repeating: "=", count: paddingLength)
        return Data(base64Encoded: normalized)
    }

    /// Encode as Base64URL (RFC 4648 §5).
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

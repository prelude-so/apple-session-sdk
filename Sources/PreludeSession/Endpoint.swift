import Foundation

/// API endpoint for ``PreludeSessionClient``. ``default``
/// resolves to the canonical Prelude API address;
/// ``custom(_:)`` accepts an explicit URL string for staging
/// or local development.
public enum Endpoint: Sendable {
    case `default`
    case custom(String)
}

extension Endpoint {
    /// String form of the configured address.
    var address: String {
        switch self {
        case .default:
            return "https://api.prelude.dev"
        case let .custom(address):
            return address
        }
    }

    /// Resolve to a `URL`, or throw a structured configuration
    /// error when the custom address fails to parse.
    func resolveBaseURL() throws -> URL {
        guard let url = URL(string: address), url.scheme != nil else {
            throw PreludeSessionError.invalidConfiguration(
                "Endpoint address `\(address)` is not a valid URL"
            )
        }
        return url
    }
}

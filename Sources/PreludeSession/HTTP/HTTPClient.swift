import Foundation

struct HTTPResponse: Sendable {
    var data: Data
    var response: HTTPURLResponse

    /// Client clock minus server clock, in seconds, derived from the
    /// `Date:` response header. Zero when missing or unparseable.
    var timeDiffSec: TimeInterval
}

/// Thin wrapper over ``HTTPSession`` with an interceptor chain.
struct HTTPClient: Sendable {
    private let session: HTTPSession
    private let clock: NowProvider

    init(
        session: HTTPSession = URLSessionHTTPSession(),
        clock: @escaping NowProvider = defaultNowProvider
    ) {
        self.session = session
        self.clock = clock
    }

    /// Raw response — does not map status codes.
    func perform(
        _ request: URLRequest,
        interceptors: [Interceptor] = []
    ) async throws -> HTTPResponse {
        let send = composeInterceptors(interceptors, baseSession: session)
        let (data, response) = try await send(request)
        return HTTPResponse(data: data, response: response, timeDiffSec: timeDiffSec(from: response))
    }

    /// Send a request with no meaningful body. Maps non-2xx to
    /// ``PreludeSessionError``.
    @discardableResult
    func sendExpectingNoBody(
        _ request: URLRequest,
        interceptors: [Interceptor] = []
    ) async throws -> TimeInterval {
        let response = try await perform(request, interceptors: interceptors)
        try HTTPClient.throwIfNonSuccess(response)
        return response.timeDiffSec
    }

    /// Send a request and decode a JSON body on 2xx.
    func sendJSON<Response: Decodable>(
        _ request: URLRequest,
        interceptors: [Interceptor] = [],
        as responseType: Response.Type,
        decoder: JSONDecoder = JSONDecoder()
    ) async throws -> (Response, HTTPResponse) {
        let response = try await perform(request, interceptors: interceptors)
        try HTTPClient.throwIfNonSuccess(response)
        do {
            let decoded = try decoder.decode(Response.self, from: response.data)
            return (decoded, response)
        } catch {
            // Do NOT include the response body. Successful
            // credential-issuing endpoints (`/refresh`,
            // `/login/finalize`, `/otp/check`, …) put access /
            // challenge tokens in the body; folding that into an
            // error message would surface secrets through any
            // host-app log or crash report. The decoder's own
            // description names the offending field, which is
            // enough to debug the schema mismatch.
            throw PreludeSessionError.generic(
                code: "decoding_failed",
                message: error.localizedDescription
            )
        }
    }

    private func timeDiffSec(from response: HTTPURLResponse) -> TimeInterval {
        guard let dateString = response.value(forHTTPHeaderField: HTTPHeader.date),
              let serverDate = HTTPClient.httpDateFormatter.date(from: dateString) else {
            return 0
        }
        return clock().timeIntervalSince(serverDate)
    }

    /// RFC 7231 `IMF-fixdate` parser.
    private static let httpDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter
    }()

    static func throwIfNonSuccess(_ response: HTTPResponse) throws {
        let status = response.response.statusCode
        if (200..<300).contains(status) { return }

        if let apiError = try? JSONDecoder().decode(APIErrorJSON.self, from: response.data) {
            throw PreludeSessionError.from(apiError: apiError)
        }

        // Don't fold the response body into the error: a
        // misbehaving proxy or app gateway can echo the original
        // request payload (containing passwords or OTP codes) in a
        // 5xx, and we don't want that in any host-app log.
        throw PreludeSessionError.generic(
            code: "http_\(status)",
            message: "HTTP \(status)"
        )
    }
}

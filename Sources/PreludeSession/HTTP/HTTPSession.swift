import Foundation

/// Underlying HTTP transport. Production uses `URLSession`; tests
/// inject a stub.
protocol HTTPSession: Sendable {
    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

struct URLSessionHTTPSession: HTTPSession {
    let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    /// `allowInsecureTLS` trusts every server cert — local development
    /// only. Never ship this enabled.
    init(allowInsecureTLS: Bool) {
        if allowInsecureTLS {
            self.session = URLSession(
                configuration: .default,
                delegate: InsecureTLSDelegate(),
                delegateQueue: nil
            )
        } else {
            self.session = .shared
        }
    }

    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw PreludeSessionError.network(underlying: URLError(.badServerResponse))
            }
            return (data, httpResponse)
        } catch let error as PreludeSessionError {
            throw error
        } catch {
            if let urlError = error as? URLError, urlError.code == .timedOut {
                throw PreludeSessionError.timeout
            }
            throw PreludeSessionError.network(underlying: error)
        }
    }
}

/// `URLSessionDelegate` that trusts every server cert. Opt-in via
/// ``URLSessionHTTPSession/init(allowInsecureTLS:)``; never ship enabled.
final class InsecureTLSDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

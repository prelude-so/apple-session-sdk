import Foundation

typealias SendFunction = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

/// Observes or modifies a request/response. Composed first-is-outermost.
protocol Interceptor: Sendable {
    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse)
}

func composeInterceptors(
    _ interceptors: [Interceptor],
    baseSession: HTTPSession
) -> SendFunction {
    var next: SendFunction = { request in
        try await baseSession.perform(request)
    }
    for interceptor in interceptors.reversed() {
        let current = next
        next = { request in
            try await interceptor.intercept(request, next: current)
        }
    }
    return next
}

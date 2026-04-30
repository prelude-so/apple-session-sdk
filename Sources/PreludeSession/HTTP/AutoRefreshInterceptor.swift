import Foundation

/// Attaches `Authorization: Bearer <access token>` and recovers from
/// 401 responses by invalidating the cache, refreshing, and retrying
/// once.
///
/// If the refresh itself fails, returns the original 401 (not the
/// retry response, never a thrown error) so upstream retry loops
/// treat auth failure as non-transient.
///
/// Auth state is routed through ``SessionRefreshing`` rather than a
/// triple of closures — named members in stack traces, easy fakes
/// in tests, and a single ``Sendable`` constraint instead of three.
struct AutoRefreshInterceptor: Interceptor {
    let refresher: any SessionRefreshing

    init(refresher: any SessionRefreshing) {
        self.refresher = refresher
    }

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        var initialRequest = request
        // Omit `Authorization` entirely when no token is cached —
        // strict proxies reject `Bearer ` (empty) before the
        // server can return a 401, breaking the refresh path.
        if let token = await refresher.currentAccessToken(), !token.isEmpty {
            initialRequest.setValue("Bearer \(token)", forHTTPHeaderField: HTTPHeader.authorization)
        }

        let (data, response) = try await next(initialRequest)

        guard response.statusCode == 401 else {
            return (data, response)
        }

        try await refresher.invalidateCurrentToken()

        let newToken: String
        do {
            newToken = try await refresher.refreshAccessToken()
        } catch {
            // Refresh failed — return the original 401 so upstream
            // retry loops see auth as non-transient. Errors on the
            // post-refresh retry below propagate so callers can
            // distinguish transport from auth issues.
            return (data, response)
        }

        var retryRequest = request
        retryRequest.setValue("Bearer \(newToken)", forHTTPHeaderField: HTTPHeader.authorization)
        return try await next(retryRequest)
    }
}

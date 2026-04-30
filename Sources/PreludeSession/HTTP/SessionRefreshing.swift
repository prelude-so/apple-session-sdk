import Foundation

/// Auth-state surface the ``AutoRefreshInterceptor`` calls into to
/// fetch the current bearer, invalidate it on a 401, and trigger a
/// refresh.
///
/// Three named members instead of three loose `@Sendable` closures
/// — readable in stack traces, one ``Sendable`` constraint to
/// reason about, and natural test doubles. The conformer (in
/// production: ``PreludeSessionClient/_Impl``) owns refresh
/// dedup; the interceptor only orchestrates.
protocol SessionRefreshing: Sendable {
    /// Cached access token, ignoring expiration. `nil` when no
    /// session is active. Returning `nil` rather than `""` lets the
    /// interceptor omit `Authorization` instead of sending an empty
    /// bearer that some proxies reject before the server can issue
    /// the 401.
    func currentAccessToken() async -> String?

    /// Mark the cached access token stale after a 401, so the
    /// next protected call refreshes.
    func invalidateCurrentToken() async throws

    /// Refresh and return the new access token. Concurrent
    /// callers must be coalesced inside the conformer — refresh
    /// tokens are single-use and a double-spend revokes the
    /// session.
    ///
    /// Disambiguated from ``PreludeSessionClient/_Impl/refresh()``
    /// (which returns ``PreludeUser``) so the actor can satisfy
    /// this requirement without conflicting overloads.
    func refreshAccessToken() async throws -> String
}

// MARK: - Production conformance

extension PreludeSessionClient._Impl: SessionRefreshing {
    func currentAccessToken() async -> String? {
        await accessTokenCache.getWithoutExpirationCheck(domain: domain)?.accessToken
    }

    func invalidateCurrentToken() async throws {
        try await invalidateSession()
    }

    func refreshAccessToken() async throws -> String {
        try await refresh().accessToken
    }
}

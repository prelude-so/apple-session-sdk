import Foundation

// MARK: - Public facade

public extension PreludeSessionClient {
    /// Change the currently-authenticated user's password.
    ///
    /// Requires the session to carry `prld:pwd:write` — obtain it
    /// via ``requestStepUp(scope:)`` + ``submitStepUpOTP(_:code:)``.
    /// Sessions without it throw
    /// ``PreludeSessionError/insufficientScope(_:)``.
    ///
    /// On success the SDK invalidates the cached token and runs a
    /// best-effort refresh so the next mint drops the now-spent
    /// scope. A thrown error means the change itself did not land;
    /// refresh-only failures are swallowed and picked up by the
    /// next authenticated call.
    func changePassword(_ newPassword: RedactedString) async throws {
        try await impl.changePassword(newPassword)
    }
}

// MARK: - Implementation

extension PreludeSessionClient._Impl {
    func changePassword(_ newPassword: RedactedString) async throws {
        var request = buildRequest(path: "me/password/reset")
        request.httpBody = try JSONEncoder().encode(
            ChangePasswordRequestBody(password: newPassword.value)
        )

        // No DPoP on `/me/password/reset`: the server only runs
        // the bearer-checking `Authorization` middleware on this
        // route — the access token + `prld:pwd:write` scope is
        // the entire credential, and the JS Web SDK reference
        // (`authenticatedMiddleware` only) matches. Sending a
        // proof would be ignored at best; on strict proxies it's
        // dead weight that can short-circuit the request before
        // the server can return its real status.
        //
        // The auto-refresh path still does the right thing: a
        // 401 here triggers ``_Impl/refresh()``, which signs
        // `/refresh` with the standard ``dpopInterceptor`` itself.
        try await httpClient.sendExpectingNoBody(
            request,
            interceptors: [autoRefreshInterceptor]
        )

        // Drop `prld:pwd:write` locally so a leaked token can't
        // change the password again without re-stepping up.
        try? await invalidateSession()
        _ = try? await refresh()
    }
}

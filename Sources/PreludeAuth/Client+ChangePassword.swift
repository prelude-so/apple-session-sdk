import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Change the currently-authenticated user's password.
    ///
    /// Requires the session to carry `prld:pwd:write` — obtain it
    /// via ``requestStepUp(scope:)`` + ``submitStepUpOTP(_:code:)``.
    /// Sessions without it throw
    /// ``PreludeAuthError/insufficientScope(_:)``.
    ///
    /// On success the SDK invalidates the cached token and runs a
    /// best-effort refresh so the next mint drops the now-spent
    /// scope. A thrown error means the change itself did not land;
    /// refresh-only failures are swallowed and picked up by the
    /// next authenticated call.
    public func changePassword(_ newPassword: RedactedString) async throws {
        try await impl.changePassword(newPassword)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func changePassword(_ newPassword: RedactedString) async throws {
        var request = buildRequest(path: "me/password/reset")
        request.httpBody = try JSONEncoder().encode(
            ChangePasswordRequestBody(password: newPassword.value)
        )

        // No DPoP on `/me/password/reset`: the route is
        // bearer-only — the access token plus the
        // `prld:pwd:write` scope is the entire credential.
        // Sending a proof would be ignored at best; on strict
        // proxies it's dead weight that can short-circuit the
        // request before the server can return its real status.
        //
        // The auto-refresh path still does the right thing: a
        // 401 here triggers ``Impl/refresh()``, which signs
        // `/refresh` with the standard ``dpopInterceptor`` itself.
        // Whichever way the request goes, the step-up that
        // granted `prld:pwd:write` is no longer in flight. Clear
        // the handle on every outcome so a stale challenge can't
        // leak after the reset attempt.
        defer { activeStepUp = nil }

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

import Foundation

// MARK: - Public facade

public extension PreludeSessionClient {
    /// Start an OTP login by sending a one-time code to
    /// `identifier`. Unauthenticated; when a ``signalsDispatcher``
    /// is configured its `dispatch_id` is attached for anti-fraud.
    func startOTPLogin(_ options: StartOTPLoginOptions) async throws {
        try await impl.startOTPLogin(options)
    }

    /// Ask the server to resend the most recently-issued OTP.
    func resendOTP() async throws {
        try await impl.resendOTP()
    }

    /// Submit an OTP code to complete the login flow.
    ///
    /// `POST /otp/check` returns a single-use `challenge_token`;
    /// the SDK exchanges it on `/login/finalize` for the access +
    /// refresh token.
    func checkOTP(_ code: String) async throws -> PreludeUser {
        try await impl.checkOTP(code)
    }
}

// MARK: - Implementation

extension PreludeSessionClient._Impl {
    func startOTPLogin(_ options: StartOTPLoginOptions) async throws {
        let dispatchId = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "otp")
        let body = StartOTPLoginRequestBody(
            identifier: options.identifier,
            loginConfigID: options.loginConfigID,
            dispatchID: dispatchId
        )
        request.httpBody = try JSONEncoder().encode(body)

        try await httpClient.sendExpectingNoBody(request)
    }

    func resendOTP() async throws {
        let request = buildRequest(path: "otp/retry")
        try await httpClient.sendExpectingNoBody(request)
    }

    func checkOTP(_ code: String) async throws -> PreludeUser {
        var request = buildRequest(path: "otp/check")
        request.httpBody = try JSONEncoder().encode(CheckOTPRequestBody(code: code))

        // Unauthenticated: the OTP code in the body is the entire
        // credential. A DPoP proof has nothing legitimate to bind
        // to here — no session key exists yet (login hasn't
        // happened) and the challenge token only materialises in
        // the response. The device-to-token binding happens one
        // step later, on `/login/finalize`.
        let (body, _) = try await httpClient.sendJSON(
            request,
            as: ChallengeTokenResponse.self
        )

        guard let challengeToken = body.challengeToken, !challengeToken.isEmpty else {
            throw PreludeSessionError.missingChallengeToken(
                "Missing challenge token from OTP check response"
            )
        }

        return try await finalizeLogin(challengeToken: challengeToken)
    }

    /// Exchange a challenge token for an access token, persist the
    /// issued refresh token, and return the authenticated user.
    /// Shared between OTP and password login flows.
    ///
    /// Only ``finalizeLogin`` and ``refresh()`` write to the
    /// refresh-token store.
    func finalizeLogin(challengeToken: String) async throws -> PreludeUser {
        // Capture the session epoch. A ``logout()`` that bumps it
        // while we're in flight invalidates whatever we'd persist;
        // bail before writing.
        let startEpoch = sessionEpoch

        var request = buildRequest(path: "login/finalize")
        request.httpBody = try JSONEncoder().encode(
            FinalizeLoginRequestBody(challengeToken: challengeToken)
        )

        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: [dpopInterceptor],
            as: RefreshTokenResponse.self
        )

        guard !body.accessToken.isEmpty else {
            throw PreludeSessionError.generic(
                code: "missing_access_token",
                message: "login/finalize response did not include an access token"
            )
        }

        guard sessionEpoch == startEpoch else {
            throw PreludeSessionError.unauthorized("session revoked during login")
        }

        if let refreshToken = http.response.value(forHTTPHeaderField: HTTPHeader.refreshToken),
           !refreshToken.isEmpty {
            let refreshTokenExpiresAt = http.response
                .value(forHTTPHeaderField: HTTPHeader.refreshTokenExpiresAt)
            try refreshTokenStore.set(
                domain: domain,
                record: RefreshTokenRecord(
                    refreshToken: refreshToken,
                    refreshTokenExpiresAt: refreshTokenExpiresAt
                )
            )
        }

        try await storeAccessToken(
            body.accessToken,
            serverExpiresAt: body.expiresAt,
            timeDiffSec: http.timeDiffSec
        )

        return try PreludeSessionClient.makeUser(accessToken: body.accessToken)
    }
}

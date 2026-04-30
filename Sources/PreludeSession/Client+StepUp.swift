import Foundation

// MARK: - Public facade

public extension PreludeSessionClient {
    /// Request a step-up to `scope`.
    ///
    /// Posts to `/stepup/request`. When the server issues an OTP
    /// challenge (the common case for `prld:pwd:write`) this also
    /// fires `POST /otp` inline so the caller's next action is
    /// "enter the code".
    ///
    /// The returned ``StepUpChallenge`` is the only handle to this
    /// attempt — pass it back to ``submitStepUpOTP(_:code:)``.
    /// Multiple in-flight step-ups on one client are supported;
    /// each caller holds its own value.
    @discardableResult
    func requestStepUp(scope: String) async throws -> StepUpChallenge {
        try await impl.requestStepUp(scope: scope)
    }

    /// Submit an OTP code for `challenge`.
    ///
    /// Returns the next ``StepUpChallenge`` for multi-step flows,
    /// or `nil` when the flow has completed and the session has
    /// been refreshed with the granted scope.
    ///
    /// On a `bad_check_code` rejection the original `challenge`
    /// stays usable up to the server's bucket limit. On any other
    /// error the challenge is dead — recover via
    /// ``requestStepUp(scope:)``.
    @discardableResult
    func submitStepUpOTP(
        _ challenge: StepUpChallenge,
        code: String
    ) async throws -> StepUpChallenge? {
        try await impl.submitStepUpOTP(challenge, code: code)
    }
}

// MARK: - Implementation

extension PreludeSessionClient._Impl {
    @discardableResult
    func requestStepUp(scope: String) async throws -> StepUpChallenge {
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "stepup/request")
        request.httpBody = try JSONEncoder().encode(
            StepUpRequestBody(scope: scope, dispatchID: dispatchID)
        )

        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: [autoRefreshInterceptor, dpopInterceptor],
            as: StepUpRequestResponse.self
        )

        if body.status == .blocked {
            return StepUpChallenge.blocked(requestedScope: scope)
        }

        guard let challengeToken = body.challengeToken, !challengeToken.isEmpty else {
            throw PreludeSessionError.missingChallengeToken(
                "Missing challenge token from stepup/request response"
            )
        }

        let challenge = try PreludeSessionClient.makeChallenge(
            from: challengeToken,
            status: body.status,
            scope: scope,
            timeDiffSec: http.timeDiffSec
        )

        try await deliverOTPIfNeeded(for: challenge)
        return challenge
    }

    @discardableResult
    func submitStepUpOTP(
        _ challenge: StepUpChallenge,
        code: String
    ) async throws -> StepUpChallenge? {
        guard !challenge.token.isEmpty else {
            throw PreludeSessionError.invalidChallengeToken(
                "Cannot submit a blocked step-up challenge"
            )
        }

        // Local expiry guard. The server would reject an expired
        // challenge as `bad_check_code` — indistinguishable from
        // a wrong code — so catching it here lets the UI surface
        // "expired, request a fresh one" cleanly.
        if challenge.expiresAt < Int(clock().timeIntervalSince1970) {
            throw PreludeSessionError.invalidChallengeToken(
                "Step-up challenge expired; call requestStepUp(scope:) again"
            )
        }

        var request = buildRequest(path: "otp/check")
        request.httpBody = try JSONEncoder().encode(
            StepUpOTPCheckRequestBody(
                code: code,
                challengeToken: challenge.token
            )
        )

        // /otp/check authenticates via the challenge token in the
        // body; challenge-scoped DPoP, no auto-refresh.
        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: [
                ChallengeDPoPInterceptor(
                    domain: domain,
                    keyStore: keyStore,
                    challengeToken: challenge.token
                )
            ],
            as: ChallengeTokenResponse.self
        )

        guard let advanced = body.challengeToken, !advanced.isEmpty else {
            throw PreludeSessionError.missingChallengeToken(
                "Missing challenge token from otp/check response"
            )
        }

        let next = try PreludeSessionClient.makeChallenge(
            from: advanced,
            status: challenge.status,
            scope: challenge.requestedScope,
            timeDiffSec: http.timeDiffSec
        )

        if next.currentStep == "completed" {
            // The post-completion refresh consumes `advanced` and
            // mints an access token carrying the granted scope.
            _ = try await refreshAfterStepUp(challengeToken: advanced)
            return nil
        }

        try await deliverOTPIfNeeded(for: next)
        return next
    }

    /// Refresh with `step_up_token` so the next access token
    /// carries the granted scope. Drains any in-flight plain
    /// refresh first — that path mints an unscoped token, so
    /// step-up can't piggy-back on its dedup slot.
    func refreshAfterStepUp(challengeToken: String) async throws -> PreludeUser {
        await drainInflightRefresh()
        try await accessTokenCache.invalidate(domain: domain)
        return try await startRefresh(stepUpToken: challengeToken).value
    }

    /// Auto-fire `POST /otp` when the next challenge step is an
    /// OTP delivery so the caller's next action is just "enter
    /// the code". Symmetric across ``requestStepUp(scope:)`` and
    /// ``submitStepUpOTP(_:code:)`` so multi-step OTP chains keep
    /// firing each step's delivery.
    private func deliverOTPIfNeeded(for challenge: StepUpChallenge) async throws {
        guard PreludeSessionClient.isOTPStep(challenge.currentStep) else { return }
        try await sendStepUpOTP(challengeToken: challenge.token)
    }

    /// Trigger OTP delivery for an in-flight challenge.
    /// Unauthenticated: the challenge token in the body identifies
    /// the caller; no DPoP.
    private func sendStepUpOTP(challengeToken: String) async throws {
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "otp")
        request.httpBody = try JSONEncoder().encode(
            StepUpOTPCreateRequestBody(
                challengeToken: challengeToken,
                dispatchID: dispatchID
            )
        )

        try await httpClient.sendExpectingNoBody(request)
    }
}

// MARK: - Step-name helpers

extension PreludeSessionClient {
    static let otpStepNames: Set<String> = ["verify_email", "verify_sms"]

    static func isOTPStep(_ currentStep: String?) -> Bool {
        guard let currentStep else { return false }
        return otpStepNames.contains(currentStep)
    }
}

// MARK: - Challenge-token decoding

extension PreludeSessionClient {
    static func makeChallenge(
        from token: String,
        status: StepUpStatus,
        scope: String,
        timeDiffSec: TimeInterval
    ) throws -> StepUpChallenge {
        let (challengeID, currentStep) = try decodeChallengeMeta(from: token)
        let expiresAt = decodeChallengeExpiry(from: token, timeDiffSec: timeDiffSec)
        return StepUpChallenge(
            status: status,
            challengeID: challengeID,
            currentStep: currentStep,
            requestedScope: scope,
            token: token,
            expiresAt: expiresAt
        )
    }

    /// Extract `challenge_id` and `current_step` from a challenge
    /// token. Both are custom claims that ``JWTClaims`` doesn't
    /// model.
    static func decodeChallengeMeta(
        from challengeToken: String
    ) throws -> (challengeID: String, currentStep: String?) {
        let jwt = try JWT.decode(challengeToken)

        guard
            let claims = try? JSONSerialization.jsonObject(
                with: jwt.payloadJSON
            ) as? [String: Any]
        else {
            throw PreludeSessionError.invalidChallengeToken(
                "Challenge token payload is not a JSON object"
            )
        }

        guard let challengeID = claims["challenge_id"] as? String else {
            throw PreludeSessionError.invalidChallengeToken(
                "Challenge token is missing `challenge_id`"
            )
        }

        // `current_step` is optional on older servers.
        let currentStep = claims["current_step"] as? String

        return (challengeID, currentStep)
    }

    /// Clock-skew-adjusted expiry from a challenge token; `0` when
    /// `exp` is missing.
    static func decodeChallengeExpiry(
        from challengeToken: String,
        timeDiffSec: TimeInterval
    ) -> Int {
        guard let jwt = try? JWT.decode(challengeToken),
              let exp = jwt.claims.exp else {
            return 0
        }
        return adjustedLocalExpiresAt(serverExpiresAt: exp, timeDiffSec: timeDiffSec)
    }
}

import Foundation

// MARK: - Public facade

public extension PreludeSessionClient {
    /// Exchange a legacy bearer token for a Prelude session.
    ///
    /// `POST /migration` accepts the legacy `token` plus a PKCE
    /// `code_challenge`; the server returns a single-use
    /// `challenge_token` which the SDK redeems on `/login/finalize`
    /// alongside the matching verifier.
    ///
    /// Idempotent: a valid cached session short-circuits the
    /// network call so re-running `migrate` after launch is safe.
    /// Concurrent callers share a single in-flight migration.
    @discardableResult
    func migrate(_ options: MigrateOptions) async throws -> PreludeUser {
        try await impl.migrate(options)
    }
}

// MARK: - Implementation

extension PreludeSessionClient._Impl {
    @discardableResult
    func migrate(_ options: MigrateOptions) async throws -> PreludeUser {
        // Fast path: already migrated by an earlier launch / call.
        if let entry = await accessTokenCache.get(domain: domain) {
            return try PreludeSessionClient.makeUser(accessToken: entry.accessToken)
        }

        if let existing = inflightMigration {
            return try await existing.value
        }

        // Unstructured `Task` decouples the migration from the
        // calling task's cancellation: a cancelled awaiter doesn't
        // abandon the legacy token mid-exchange.
        let task = Task<PreludeUser, Error> {
            defer { self.inflightMigration = nil }
            return try await self.doMigrate(token: options.token)
        }
        inflightMigration = task
        return try await task.value
    }

    private func doMigrate(token: String) async throws -> PreludeUser {
        // Re-check after taking the inflight slot — a sibling may
        // have populated the cache before we got here.
        if let entry = await accessTokenCache.get(domain: domain) {
            return try PreludeSessionClient.makeUser(accessToken: entry.accessToken)
        }

        let codeVerifier = try PKCE.generateCodeVerifier()
        let codeChallenge = PKCE.codeChallenge(for: codeVerifier)
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "migration")
        request.httpBody = try JSONEncoder().encode(
            MigrateRequestBody(
                token: token,
                codeChallenge: codeChallenge,
                dispatchID: dispatchID
            )
        )

        // Unauthenticated: the legacy token in the body is the
        // entire credential, mirroring the OTP-check shape.
        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [],
            as: ChallengeTokenResponse.self
        )

        guard let challengeToken = body.challengeToken,
              !challengeToken.isEmpty else {
            throw PreludeSessionError.missingChallengeToken(
                "Missing challenge token from migration response"
            )
        }

        return try await finalizeLogin(
            challengeToken: challengeToken,
            codeVerifier: codeVerifier
        )
    }
}

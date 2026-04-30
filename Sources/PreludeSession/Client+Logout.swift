import Foundation

// MARK: - Public facade

public extension PreludeSessionClient {
    /// Revoke the current session on the server and wipe every
    /// domain-scoped credential this client owns.
    ///
    /// Local state is wiped before `POST /revoke` fires. A failed
    /// server round-trip therefore still leaves the client locally
    /// logged out; concurrent ``refresh()`` can't resurrect the
    /// session — its target stores are already empty.
    func logout() async throws {
        try await impl.logout()
    }
}

// MARK: - Implementation

extension PreludeSessionClient._Impl {
    func logout() async throws {
        // Wait for any in-flight refresh so our snapshot reads
        // the rotated refresh token, not the pre-rotation one.
        if let inflight = inflightRefresh {
            _ = try? await inflight.value
        }

        if let existing = inflightLogout {
            return try await existing.value
        }

        // Bump the epoch after the dedup check so coalesced callers
        // don't bump redundantly. A refresh started under the old
        // value will see the mismatch and bail.
        sessionEpoch += 1

        let task = Task<Void, Error> { try await self.doLogout() }
        inflightLogout = task
        defer { inflightLogout = nil }
        try await task.value
    }

    private func doLogout() async throws {
        // Snapshot what /revoke needs before wiping the stores so
        // the request can still be DPoP-signed afterwards.
        //
        // `try?` on the reads is load-bearing: a corrupted Keychain
        // item can fail `get` but still succeed `delete`, so the
        // wipe must run regardless. Losing a snapshot just means
        // we can't sign /revoke; leaving the user stuck logged-in
        // is worse than an unrevoked server session.
        let dpopHandle = try? keyStore.get(domain: domain)
        let dpopNonce = try? keyStore.getNonce(domain: domain)
        let refreshRecord = try? refreshTokenStore.get(domain: domain)
        let refreshToken = refreshRecord?.refreshToken

        let wipeError: Error?
        do {
            try await clearAllStores()
            wipeError = nil
        } catch {
            wipeError = error
        }

        // No credentials on file — nothing to revoke.
        guard let dpopHandle, let refreshToken, !refreshToken.isEmpty else {
            if let wipeError { throw wipeError }
            return
        }

        // Sign /revoke inline from the snapshot. The standard
        // ``DPoPInterceptor`` would provision a fresh keypair
        // against the now-empty keystore, whose fingerprint
        // wouldn't match the session's pinned one server-side.
        var request = buildRequest(path: "revoke")
        request.setValue(refreshToken, forHTTPHeaderField: HTTPHeader.refreshToken)

        guard let htu = DPoPInterceptor.htuURL(for: request) else {
            throw PreludeSessionError.invalidConfiguration("URLRequest is missing a URL")
        }
        let proof = try DefaultDPoPProofBuilder().create(
            key: dpopHandle,
            method: request.httpMethod ?? "POST",
            url: htu,
            nonce: dpopNonce,
            jti: nil,
            now: Date()
        )
        request.setValue(proof, forHTTPHeaderField: HTTPHeader.dpop)

        // If /revoke also throws, surface the wipe error in
        // preference: the local credential left behind on the
        // device is more security-critical than an unrevoked
        // server session, which TTLs out on its own.
        do {
            try await httpClient.sendExpectingNoBody(request)
        } catch {
            if let wipeError { throw wipeError }
            throw error
        }

        if let wipeError { throw wipeError }
    }

    /// Delete every domain-scoped credential. Best-effort — every
    /// delete is attempted regardless of earlier failures, then the
    /// first captured error is rethrown.
    func clearAllStores() async throws {
        var firstError: Error?

        func attempt(_ body: () throws -> Void) {
            do { try body() } catch {
                if firstError == nil { firstError = error }
            }
        }

        // Inline the cache wipe rather than threading async into
        // `attempt`: the actor cache is the only async store, and
        // its failure mode is identical to the synchronous ones.
        attempt { try keyStore.delete(domain: domain) }
        attempt { try keyStore.deleteNonce(domain: domain) }
        attempt { try refreshTokenStore.delete(domain: domain) }
        do {
            try await accessTokenCache.clear(domain: domain)
        } catch {
            if firstError == nil { firstError = error }
        }

        if let firstError { throw firstError }
    }
}

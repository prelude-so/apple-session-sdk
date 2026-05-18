import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Profile claims of the currently-cached access token, or
    /// `nil` if none. Ignores expiration so the app can render
    /// the profile during a refresh.
    public var profile: PreludeProfile? {
        get async { await impl.profile }
    }

    /// Session identifier of the currently-cached access token,
    /// sourced from the JWT `sid` claim.
    public var sessionID: String? {
        get async { await impl.sessionID }
    }

    /// Raw cached access token, or `nil` if none. Does not check
    /// expiration — production code gets a fresh token wired in
    /// automatically via ``AutoRefreshInterceptor``.
    public var accessToken: String? {
        get async { await impl.accessToken }
    }

    /// Absolute expiration of the cached access token, already
    /// clock-skew-adjusted at storage time. `nil` when no token
    /// is cached. Returns even for expired tokens so diagnostic
    /// UIs can render "expired Ns ago".
    public var accessTokenExpiresAt: Date? {
        get async { await impl.accessTokenExpiresAt }
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    var profile: PreludeProfile? {
        get async {
            guard let entry = await accessTokenCache.getWithoutExpirationCheck(domain: domain) else {
                return nil
            }
            guard let jwt = try? JWT.decode(entry.accessToken) else {
                return nil
            }
            return PreludeProfile.from(jwt: jwt)
        }
    }

    var sessionID: String? {
        get async { await profile?.sessionID }
    }

    var accessToken: String? {
        get async {
            await accessTokenCache.getWithoutExpirationCheck(domain: domain)?.accessToken
        }
    }

    var accessTokenExpiresAt: Date? {
        get async {
            guard let entry = await accessTokenCache.getWithoutExpirationCheck(domain: domain) else {
                return nil
            }
            return Date(timeIntervalSince1970: TimeInterval(entry.expiresAt))
        }
    }
}

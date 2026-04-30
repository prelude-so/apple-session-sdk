import Foundation

/// Value-typed facade over the session actor.
///
/// Sendable, with a synchronous throwing init, so it propagates
/// through SwiftUI surfaces (`@State`, `@Environment`) without
/// ceremony and leaves room for `@Observable` adoption. Mutable
/// state lives on a nested actor; copies of the facade share the
/// same actor instance.
public struct PreludeSessionClient: Sendable {
    let impl: _Impl

    /// - Parameters:
    ///   - endpoint: API endpoint. Defaults to the canonical
    ///     Prelude address; pass `.custom("https://…")` for
    ///     staging or local development.
    ///   - hostOverride: canonical authority used as the DPoP
    ///     `htu`, the `Host:` header, and the Keychain
    ///     partition key. Set when the connection address
    ///     differs from what the server sees (e.g. localhost
    ///     forwarding behind a reverse proxy). `nil` derives
    ///     these from the endpoint's host.
    ///   - signalsDispatcher: optional anti-fraud dispatcher
    ///     wired into unauthenticated login calls.
    ///   - timeout: per-request timeout, in seconds.
    ///   - allowInsecureTLS: trust every server cert. Local
    ///     development only.
    public init(
        endpoint: Endpoint = .default,
        hostOverride: String? = nil,
        signalsDispatcher: PreludeSignalsDispatcher? = nil,
        timeout: TimeInterval = 10.0,
        allowInsecureTLS: Bool = false
    ) throws {
        self.impl = try _Impl(
            baseURL: try endpoint.resolveBaseURL(),
            hostOverride: hostOverride,
            signalsDispatcher: signalsDispatcher,
            timeout: timeout,
            httpSession: URLSessionHTTPSession(allowInsecureTLS: allowInsecureTLS),
            clock: defaultNowProvider,
            keyStore: DPoPKeyStoreFactory.makeDefault(),
            refreshTokenStore: RefreshTokenStore(),
            accessTokenCache: AccessTokenCache()
        )
    }

    /// Test-only init that takes injected dependencies.
    init(
        baseURL: URL,
        hostOverride: String?,
        signalsDispatcher: PreludeSignalsDispatcher?,
        timeout: TimeInterval,
        httpSession: HTTPSession,
        clock: @escaping NowProvider,
        keyStore: DPoPKeyStore,
        refreshTokenStore: RefreshTokenStore,
        accessTokenCache: AccessTokenCache
    ) throws {
        self.impl = try _Impl(
            baseURL: baseURL,
            hostOverride: hostOverride,
            signalsDispatcher: signalsDispatcher,
            timeout: timeout,
            httpSession: httpSession,
            clock: clock,
            keyStore: keyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache
        )
    }

    /// Mark the local access token expired so the next protected
    /// call refreshes. Does NOT revoke the session on the server
    /// or wipe the refresh token — use ``logout()`` for that.
    /// The cached token entry stays retrievable so the client
    /// can render profile data while a refresh runs.
    public func invalidateSession() async throws {
        try await impl.invalidateSession()
    }

    // MARK: - Static helpers (pure)

    /// Adjust a server-reported expiration (Unix seconds) to the
    /// local clock by applying the observed skew. `floor` (in
    /// `Double` space) preserves the "never overestimate" invariant
    /// for negative skews.
    static func adjustedLocalExpiresAt(
        serverExpiresAt: Int,
        timeDiffSec: TimeInterval
    ) -> Int {
        Int(floor(Double(serverExpiresAt) + timeDiffSec))
    }

    /// Decode a ``PreludeUser`` from an access token.
    static func makeUser(accessToken: String) throws -> PreludeUser {
        let jwt = try JWT.decode(accessToken)
        return PreludeUser(
            accessToken: accessToken,
            profile: PreludeProfile.from(jwt: jwt)
        )
    }
}

extension PreludeSessionClient {
    /// Owns the mutable session state; serialises access via actor
    /// isolation. Internal: never surfaced from the public facade.
    actor _Impl {
        /// Keychain partition key. Derived from ``hostOverride``
        /// when set, else from ``baseURL``'s host.
        let domain: String

        /// Canonical-authority hint. When set it is (1) the
        /// Keychain partition key, (2) the DPoP `htu` authority,
        /// and (3) written as the `Host:` header on every
        /// outgoing request.
        ///
        /// Caveat: `URLSession` may silently overwrite the `Host:`
        /// header. In practice an `/etc/hosts` entry on the
        /// simulator plus a canonical ``baseURL`` is more reliable.
        let hostOverride: String?

        let signalsDispatcher: PreludeSignalsDispatcher?
        let timeout: TimeInterval
        let baseURL: URL

        let httpClient: HTTPClient
        let keyStore: DPoPKeyStore
        let refreshTokenStore: RefreshTokenStore
        let accessTokenCache: AccessTokenCache
        let clock: NowProvider

        /// Concurrent callers (explicit ``refresh()`` and the
        /// 401-driven interceptor) share this task so the
        /// single-use refresh token is never spent twice.
        var inflightRefresh: Task<PreludeUser, Error>?

        /// Coalesces concurrent ``logout()`` callers onto a single
        /// `POST /revoke`.
        var inflightLogout: Task<Void, Error>?

        /// Bumped on every ``logout()``. ``refresh()`` captures it
        /// at entry and bails before persisting rotated tokens if
        /// logout moved the counter mid-flight.
        var sessionEpoch: Int = 0

        init(
            baseURL: URL,
            hostOverride: String?,
            signalsDispatcher: PreludeSignalsDispatcher?,
            timeout: TimeInterval,
            httpSession: HTTPSession,
            clock: @escaping NowProvider,
            keyStore: DPoPKeyStore,
            refreshTokenStore: RefreshTokenStore,
            accessTokenCache: AccessTokenCache
        ) throws {
            let derivedDomain: String
            if let hostOverride, !hostOverride.isEmpty {
                derivedDomain = hostOverride
            } else if let host = baseURL.host, !host.isEmpty {
                derivedDomain = host
            } else {
                throw PreludeSessionError.invalidConfiguration(
                    "baseURL must have a host, or hostOverride must be non-empty"
                )
            }

            self.domain = derivedDomain
            self.hostOverride = hostOverride
            self.signalsDispatcher = signalsDispatcher
            self.timeout = timeout
            self.baseURL = baseURL.appendingPathComponent("v1/session")
            self.httpClient = HTTPClient(session: httpSession, clock: clock)
            self.keyStore = keyStore
            self.refreshTokenStore = refreshTokenStore
            self.accessTokenCache = accessTokenCache
            self.clock = clock

            // Warm the in-memory cache so a cold start can render
            // the profile and skip a refresh round-trip when valid.
            //
            // Fire-and-forget: the actor's queue serialises this
            // hydrate before any subsequent isolated message from
            // the same caller, so the typical "construct ⇒ read"
            // path still sees the warmed entry. A first read that
            // races ahead just costs one extra refresh round-trip,
            // which the original synchronous warm wouldn't have
            // saved anyway when the Keychain was empty.
            Task { [accessTokenCache, derivedDomain] in
                await accessTokenCache.hydrate(domain: derivedDomain)
            }
        }

        var dpopInterceptor: DPoPInterceptor {
            DPoPInterceptor(domain: domain, keyStore: keyStore)
        }

        /// Auto-refresh interceptor bound to this actor's cache and
        /// refresh flow. Attach alongside ``dpopInterceptor`` only
        /// on protected endpoints — unauthenticated routes (e.g.
        /// `/otp`) must not use it.
        ///
        /// `self` is passed strongly: the interceptor is built on
        /// demand and lives only for the duration of the request,
        /// so it can't extend the actor's lifetime past the
        /// caller's.
        var autoRefreshInterceptor: AutoRefreshInterceptor {
            AutoRefreshInterceptor(refresher: self)
        }

        func invalidateSession() async throws {
            try await accessTokenCache.invalidate(domain: domain)
        }

        func buildRequest(path: String, method: String = "POST") -> URLRequest {
            var request = URLRequest(url: baseURL.appendingPathComponent(path))
            request.httpMethod = method
            request.timeoutInterval = timeout
            // Only advertise Content-Type for methods that carry a
            // body. Strict proxies reject Content-Type without one.
            if ["POST", "PUT", "PATCH"].contains(method.uppercased()) {
                request.setValue("application/json", forHTTPHeaderField: HTTPHeader.contentType)
            }
            request.setValue("application/json", forHTTPHeaderField: HTTPHeader.accept)
            // Identify the SDK + OS to server-side telemetry without
            // shadowing the host app's own User-Agent on requests it
            // owns: this only applies to URLRequests we build here.
            request.setValue(PreludeSessionSDK.userAgent, forHTTPHeaderField: HTTPHeader.userAgent)
            if let hostOverride, !hostOverride.isEmpty {
                request.setValue(hostOverride, forHTTPHeaderField: HTTPHeader.host)
            }
            return request
        }

        func dispatchSignalsIfConfigured() async throws -> String? {
            guard let signalsDispatcher else { return nil }
            return try await signalsDispatcher.dispatch()
        }

        /// Persist a fresh access token, correcting for observed
        /// clock skew so the stored expiry compares correctly
        /// against the local device clock.
        func storeAccessToken(
            _ accessToken: String,
            serverExpiresAt: Int,
            timeDiffSec: TimeInterval
        ) async throws {
            try await accessTokenCache.set(
                domain: domain,
                entry: AccessTokenEntry(
                    accessToken: accessToken,
                    expiresAt: PreludeSessionClient.adjustedLocalExpiresAt(
                        serverExpiresAt: serverExpiresAt,
                        timeDiffSec: timeDiffSec
                    )
                )
            )
        }
    }
}

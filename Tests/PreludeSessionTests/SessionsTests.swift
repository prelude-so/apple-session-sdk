import Foundation
import XCTest
@testable import PreludeSession

/// `listSessions` / `revokeSessions` — wire shape, header
/// attachment policy, and local-wipe semantics.
final class SessionsTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "sessions-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil
        baseURL = nil
        clock = nil
        super.tearDown()
    }

    /// Payload `{"sub":"user-1","sid":"sess-current"}` — the SDK
    /// reads `sid` to decide whether revoking a specific session
    /// should also wipe local credentials.
    private let accessTokenWithSID =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLWN1cnJlbnQifQ.sig"

    // MARK: - listSessions

    func test_listSessions_decodesPaginatedResponse() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/list",
            response: .json([
                "sessions": [
                    [
                        "id": "sess-1",
                        "device_model": "iPhone15,2",
                        "device_type": "mobile",
                        "os_version": "17.4",
                        "country_code": "US",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_seen_at": "2026-05-01T12:00:00Z",
                        "expires_at": "2026-06-01T00:00:00Z",
                    ],
                    [
                        "id": "sess-2",
                        "device_model": "MacBookPro18,3",
                        "device_type": "desktop",
                        "os_version": "14.5",
                        "country_code": "FR",
                        "created_at": "2026-02-01T00:00:00Z",
                        "last_seen_at": "2026-05-02T08:00:00Z",
                        "expires_at": "2026-07-01T00:00:00Z",
                    ],
                ],
                "total": 2,
                "limit": 10,
                "offset": 0,
            ])
        )

        let page = try await fixture.client.listSessions()

        XCTAssertEqual(page.total, 2)
        XCTAssertEqual(page.limit, 10)
        XCTAssertEqual(page.offset, 0)
        XCTAssertEqual(page.sessions.count, 2)
        XCTAssertEqual(page.sessions[0].id, "sess-1")
        XCTAssertEqual(page.sessions[0].deviceType, .mobile)
        XCTAssertEqual(page.sessions[1].deviceType, .desktop)
    }

    /// Unknown `device_type` values must round-trip as `.unknown`
    /// rather than failing decode — protects callers from a future
    /// server-side enum addition.
    func test_listSessions_tolerantToUnknownDeviceType() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/list",
            response: .json([
                "sessions": [[
                    "id": "sess-1",
                    "device_model": "Vision Pro",
                    "device_type": "headset",
                    "os_version": "1.0",
                    "country_code": "US",
                    "created_at": "2026-01-01T00:00:00Z",
                    "last_seen_at": "2026-05-01T00:00:00Z",
                    "expires_at": "2026-06-01T00:00:00Z",
                ]],
                "total": 1,
                "limit": 10,
                "offset": 0,
            ])
        )

        let page = try await fixture.client.listSessions()
        XCTAssertEqual(page.sessions.first?.deviceType, .unknown)
    }

    func test_listSessions_appendsLimitAndOffsetQuery() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/list",
            response: .json([
                "sessions": [], "total": 0, "limit": 5, "offset": 20,
            ])
        )

        _ = try await fixture.client.listSessions(.init(limit: 5, offset: 20))

        let recorded = fixture.http.requests(forPath: "/v1/session/me/list")
        XCTAssertEqual(recorded.count, 1)
        let query = recorded.first?.url?.query ?? ""
        XCTAssertTrue(query.contains("limit=5"), "got query=\(query)")
        XCTAssertTrue(query.contains("offset=20"), "got query=\(query)")
    }

    func test_listSessions_omitsQueryWhenNoOptions() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/list",
            response: .json([
                "sessions": [], "total": 0, "limit": 10, "offset": 0,
            ])
        )

        _ = try await fixture.client.listSessions()

        let recorded = fixture.http.requests(forPath: "/v1/session/me/list")
        XCTAssertNil(recorded.first?.url?.query, "no options ⇒ no query string")
    }

    func test_listSessions_attachesBearer_noDPoP() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/list",
            response: .json([
                "sessions": [], "total": 0, "limit": 10, "offset": 0,
            ])
        )

        _ = try await fixture.client.listSessions()

        let recorded = fixture.http.requests(forPath: "/v1/session/me/list").first
        XCTAssertEqual(recorded?.value(forHTTPHeaderField: HTTPHeader.authorization), "Bearer access-v1")
        XCTAssertNil(
            recorded?.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/me/list is bearer-only — no DPoP attached"
        )
        XCTAssertEqual(recorded?.httpMethod, "GET")
    }

    func test_listSessions_propagatesUnauthorized() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/list",
            response: .json(
                ["code": "unauthorized", "message": "expired"],
                statusCode: 401
            )
        )
        // No `/refresh` stub: the auto-refresh attempt fails, so
        // the original 401 surfaces as `unauthorized`.

        do {
            _ = try await fixture.client.listSessions()
            XCTFail("expected unauthorized")
        } catch PreludeSessionError.unauthorized {
            // expected
        }
    }

    // MARK: - revokeSessions

    func test_revokeSessions_session_byID_passesQueryParams() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.session(id: "sess-other"))

        let recorded = fixture.http.requests(forPath: "/v1/session/me/revoke").first
        let query = recorded?.url?.query ?? ""
        XCTAssertTrue(query.contains("target=session"), "got query=\(query)")
        XCTAssertTrue(query.contains("session_id=sess-other"), "got query=\(query)")
        XCTAssertEqual(recorded?.httpMethod, "POST")
    }

    func test_revokeSessions_others_doesNotWipeLocalState() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.others)

        let recorded = fixture.http.requests(forPath: "/v1/session/me/revoke").first
        XCTAssertEqual(recorded?.url?.query, "target=others")
        // Current session survives `others` — local credentials stay put.
        let cached = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNotNil(cached)
        XCTAssertNotNil(try fixture.refreshTokenStore.get(domain: domain))
    }

    func test_revokeSessions_all_wipesLocalState() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.all)

        try await fixture.assertWiped()
    }

    func test_revokeSessions_mine_wipesLocalState() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.mine)

        try await fixture.assertWiped()
    }

    /// Revoking the same session id as the cached `sid` claim must
    /// wipe local state — otherwise the next refresh would race a
    /// server-side revoked token.
    func test_revokeSessions_session_matchingCurrent_wipesLocalState() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        // Override the access token with one that carries `sid=sess-current`.
        try await fixture.accessTokenCache.set(
            domain: domain,
            entry: AccessTokenEntry(
                accessToken: accessTokenWithSID,
                expiresAt: Int(clock().timeIntervalSince1970) + 3600
            )
        )

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.session(id: "sess-current"))

        try await fixture.assertWiped()
    }

    /// Revoking a different session id keeps local state — the
    /// caller is just managing their other devices.
    func test_revokeSessions_session_notMatchingCurrent_keepsLocalState() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        try await fixture.accessTokenCache.set(
            domain: domain,
            entry: AccessTokenEntry(
                accessToken: accessTokenWithSID,
                expiresAt: Int(clock().timeIntervalSince1970) + 3600
            )
        )

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.session(id: "sess-other-device"))

        let cached = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(cached?.accessToken, accessTokenWithSID)
        XCTAssertNotNil(try fixture.refreshTokenStore.get(domain: domain))
    }

    func test_revokeSessions_attachesBearer_noDPoP() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.others)

        let recorded = fixture.http.requests(forPath: "/v1/session/me/revoke").first
        XCTAssertEqual(recorded?.value(forHTTPHeaderField: HTTPHeader.authorization), "Bearer access-v1")
        XCTAssertNil(
            recorded?.value(forHTTPHeaderField: HTTPHeader.dpop),
            "/me/revoke is bearer-only — no DPoP attached"
        )
    }

    /// A failed `/me/revoke` must NOT wipe local state: the server
    /// didn't terminate the session, so the client's credentials
    /// are still valid.
    func test_revokeSessions_serverError_leavesLocalStateIntact() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/me/revoke",
            response: .json(
                ["code": "internal_server_error", "message": "boom"],
                statusCode: 500
            )
        )

        do {
            try await fixture.client.revokeSessions(.all)
            XCTFail("expected internalServerError")
        } catch PreludeSessionError.internalServerError {
            // expected
        }

        let cached = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNotNil(cached, "failed revoke must not wipe local state")
        XCTAssertNotNil(try fixture.refreshTokenStore.get(domain: domain))
    }

    /// Empty and whitespace-only ids are rejected up front rather
    /// than relayed to the server as `session_id=` or
    /// `session_id=%20`. The Swift type still admits both
    /// strings, so guard explicitly with a runtime check.
    func test_revokeSessions_session_blankID_throwsInvalidConfiguration() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        for blank in ["", " ", "\t", "  \n "] {
            do {
                try await fixture.client.revokeSessions(.session(id: blank))
                XCTFail("expected invalidConfiguration for id=\"\(blank)\"")
            } catch PreludeSessionError.invalidConfiguration {
                // expected
            }
        }

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/me/revoke"),
            0,
            "no network call when the local guard rejects the input"
        )
    }

    /// After a wiping revoke, a follow-up `refresh()` finds empty
    /// stores and short-circuits without touching the network —
    /// the same post-wipe invariant `logout()` relies on, but
    /// reasserted on the `revokeSessions` path so a regression
    /// here surfaces locally.
    func test_revokeSessions_postWipeRefresh_doesNotHitNetwork() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(path: "/v1/session/me/revoke", response: .noContent)

        try await fixture.client.revokeSessions(.all)
        try await fixture.assertWiped()

        do {
            _ = try await fixture.client.refresh()
            XCTFail("post-wipe refresh should fail without a token")
        } catch PreludeSessionError.unauthorized {
            // expected
        }
        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/refresh"),
            0,
            "post-wipe refresh must not hit the network"
        )
    }

    // MARK: - Pure decision

    /// Pin the wipe-decision matrix so the contract
    /// can't drift silently.
    func test_shouldWipeAfterRevoke_matrix() {
        typealias Impl = PreludeSessionClient._Impl

        XCTAssertTrue(Impl.shouldWipeAfterRevoke(target: .all, currentSessionID: "x"))
        XCTAssertTrue(Impl.shouldWipeAfterRevoke(target: .all, currentSessionID: nil))
        XCTAssertTrue(Impl.shouldWipeAfterRevoke(target: .mine, currentSessionID: "x"))
        XCTAssertTrue(Impl.shouldWipeAfterRevoke(target: .mine, currentSessionID: nil))

        XCTAssertFalse(Impl.shouldWipeAfterRevoke(target: .others, currentSessionID: "x"))
        XCTAssertFalse(Impl.shouldWipeAfterRevoke(target: .others, currentSessionID: nil))

        XCTAssertTrue(Impl.shouldWipeAfterRevoke(target: .session(id: "abc"), currentSessionID: "abc"))
        XCTAssertFalse(Impl.shouldWipeAfterRevoke(target: .session(id: "abc"), currentSessionID: "xyz"))
        XCTAssertFalse(Impl.shouldWipeAfterRevoke(target: .session(id: "abc"), currentSessionID: nil))
    }
}

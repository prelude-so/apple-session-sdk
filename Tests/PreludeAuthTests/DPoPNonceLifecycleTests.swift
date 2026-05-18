import Foundation
@testable import PreludeAuth
import XCTest

/// Nonce lifecycle around `use_dpop_nonce`, 2xx overwrites, and
/// cold start. Verifies the persisted nonce is the canonical
/// source of truth — not in-memory state lost on app exit.
final class DPoPNonceLifecycleTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "dpop-nonce-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s"

    // MARK: - Persisted before retry; survives a retry failure

    /// `use_dpop_nonce` 400 must set the new nonce BEFORE the
    /// retry fires. If the retry then throws, the nonce is still
    /// cached so the next call doesn't repeat the dance.
    func test_useDpopNonce_persistsNonceBeforeRetry_evenIfRetryFails() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        let challenge = try JSONSerialization.data(withJSONObject: [
            "code": "use_dpop_nonce", "message": "rotate",
        ])
        let serverFailure = try JSONSerialization.data(withJSONObject: [
            "code": "internal_server_error", "message": "boom",
        ])
        fixture.http.installSequence(
            path: "/v1/session/refresh",
            responses: [
                StubHTTPSession.CannedResponse(
                    statusCode: 400, body: challenge,
                    headers: [
                        "Content-Type": "application/json",
                        HTTPHeader.dpopNonce: "n-fresh",
                    ]
                ),
                StubHTTPSession.CannedResponse(
                    statusCode: 500, body: serverFailure,
                    headers: ["Content-Type": "application/json"]
                ),
            ]
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("expected retry to surface the 500")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 2)
        XCTAssertEqual(
            try fixture.keyStore.getNonce(domain: domain), "n-fresh",
            "fresh nonce must persist even when the retry fails"
        )
    }

    // MARK: - 2xx overrides previous

    /// A successful response carrying a new `DPoP-Nonce` must
    /// overwrite whatever was cached.
    func test_successfulResponseWithNonce_overridesPrevious() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(nonce: "n-old", accessTokenExpired: true)

        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [
                    HTTPHeader.refreshToken: "r2",
                    HTTPHeader.dpopNonce: "n-new",
                ]
            )
        )

        _ = try await fixture.client.refresh()

        XCTAssertEqual(try fixture.keyStore.getNonce(domain: domain), "n-new")
    }

    // MARK: - Cold start

    /// Persisted nonce must replay across a fresh client built
    /// against the same Keychain backend. The first request after
    /// "restart" carries the nonce — no `use_dpop_nonce` round-
    /// trip needed.
    func test_nonce_survivesColdStart() async throws {
        let backend = InMemoryKeychainBackend()

        // Phase 1: warm a session, harvest a nonce on /refresh.
        let warm = try makeFixture(backend: backend)
        try await warm.prePopulate(accessTokenExpired: true)
        warm.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [
                    HTTPHeader.refreshToken: "r2",
                    HTTPHeader.dpopNonce: "n-persisted",
                ]
            )
        )
        _ = try await warm.client.refresh()
        XCTAssertEqual(try warm.keyStore.getNonce(domain: domain), "n-persisted")

        // Phase 2: rebuild every store against the same backend
        // — simulates a cold app launch reading from disk.
        let cold = try makeFixture(backend: backend)
        try await cold.prePopulate(accessTokenExpired: true) // re-arm refresh token
        cold.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "r3"]
            )
        )

        _ = try await cold.client.refresh()

        XCTAssertEqual(
            cold.http.requestCount(forPath: "/v1/session/refresh"), 1,
            "cold start must replay the persisted nonce — no use_dpop_nonce round-trip"
        )
        let req = try XCTUnwrap(
            cold.http.requests(forPath: "/v1/session/refresh").first
        )
        let proof = try XCTUnwrap(req.value(forHTTPHeaderField: HTTPHeader.dpop))
        XCTAssertEqual(
            try StepUpFixtures.decodeJWTPayload(proof)["nonce"] as? String,
            "n-persisted",
            "first proof after cold start must include the persisted nonce"
        )
    }

    // MARK: - Helpers

    private func makeFixture(backend: KeychainBackend) throws -> Fixture {
        try Fixture.make(domain: domain, baseURL: baseURL, clock: clock, backend: backend)
    }
}

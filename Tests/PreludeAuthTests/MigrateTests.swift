import Foundation
@testable import PreludeAuth
import XCTest

final class MigrateTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "migrate-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    /// Well-formed, unsigned JWT — `JWT.decode` reads the payload only.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    // MARK: - Happy path

    func test_migrate_returnsUser_andPersistsRefreshToken() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        fixture.http.install(
            path: "/v1/session/migration",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        let user = try await fixture.client.migrate(MigrateOptions(token: "legacy-bearer"))

        XCTAssertEqual(user.profile.userID, "user-1")
        XCTAssertEqual(
            try fixture.refreshTokenStore.get(domain: domain)?.refreshToken,
            "refresh-v1"
        )
    }

    // MARK: - PKCE binding

    func test_migrate_sendsPkceChallenge_andMatchingVerifier() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        fixture.http.install(
            path: "/v1/session/migration",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        _ = try await fixture.client.migrate(MigrateOptions(token: "legacy-bearer"))

        let migrationBody = try Self.json(fixture.http.requests(forPath: "/v1/session/migration").first?.httpBody)
        let finalizeBody = try Self.json(fixture.http.requests(forPath: "/v1/session/login/finalize").first?.httpBody)

        XCTAssertEqual(migrationBody["token"] as? String, "legacy-bearer")
        let challenge = try XCTUnwrap(migrationBody["code_challenge"] as? String)
        let verifier = try XCTUnwrap(finalizeBody["code_verifier"] as? String)
        XCTAssertEqual(challenge, PKCE.codeChallenge(for: verifier))
        XCTAssertEqual(finalizeBody["challenge_token"] as? String, "challenge-abc")
    }

    // MARK: - Cache short-circuit

    func test_migrate_shortCircuits_whenSessionAlreadyCached() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.accessTokenCache.set(
            domain: domain,
            entry: AccessTokenEntry(
                accessToken: jwt,
                expiresAt: Int(clock().timeIntervalSince1970) + 3600
            )
        )

        let user = try await fixture.client.migrate(MigrateOptions(token: "legacy-bearer"))

        XCTAssertEqual(user.profile.userID, "user-1")
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/migration"), 0)
    }

    // MARK: - Error mapping

    func test_migrate_missingChallengeToken_throwsStructured() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/migration",
            response: .json([:])
        )

        do {
            _ = try await fixture.client.migrate(MigrateOptions(token: "legacy-bearer"))
            XCTFail("expected missingChallengeToken")
        } catch PreludeAuthError.missingChallengeToken {
            // expected
        }
    }

    // MARK: - Concurrent callers

    func test_migrate_concurrentCallers_shareSingleMigration() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        fixture.http.install(
            path: "/v1/session/migration",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )
        fixture.http.installGate(path: "/v1/session/migration")

        async let firstMigrate = fixture.client.migrate(MigrateOptions(token: "legacy-bearer"))
        async let secondMigrate = fixture.client.migrate(MigrateOptions(token: "legacy-bearer"))

        try await waitUntil { fixture.http.requestCount(forPath: "/v1/session/migration") >= 1 }
        fixture.http.releaseGate(path: "/v1/session/migration")

        let users = try await [firstMigrate, secondMigrate]
        XCTAssertEqual(users[0].accessToken, users[1].accessToken)
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/migration"), 1)
    }

    // MARK: - Helpers

    private static func json(_ data: Data?) throws -> [String: Any] {
        let raw = try XCTUnwrap(data)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
    }

    private func waitUntil(
        timeout: TimeInterval = 2,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ condition: @escaping () -> Bool
    ) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if condition() {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out", file: file, line: line)
    }
}

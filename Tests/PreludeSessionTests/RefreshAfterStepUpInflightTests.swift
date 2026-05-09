import Foundation
import XCTest
@testable import PreludeSession

/// Single-flight invariant for the post-completion refresh
/// (``PreludeSessionClient/_Impl/refreshAfterStepUp``).
///
/// The helper invalidates the access-token cache and then mints
/// a scoped access token by sending `step_up_token` on
/// `/refresh`. A concurrent `refresh()` that lands during the
/// invalidate suspension must not race the scoped refresh: two
/// `/refresh` round-trips carrying the same single-use refresh
/// token trips the server's reuse-detection and revokes the
/// family.
///
/// The contract is *no concurrent reuse*, not "exactly one
/// `/refresh` hop". A sibling that legitimately lands first
/// can rotate `refresh-v1 → refresh-v2`; the post-completion
/// path then rotates `v2 → v3` sequentially. Both hops are
/// fine; what's not fine is two hops carrying `v1`.
final class RefreshAfterStepUpInflightTests: XCTestCase {
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        clock = nil
        super.tearDown()
    }

    private let scopedJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s"

    private var otpToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "verify_email",
            "jti": "jti-otp", "exp": 2_000_000,
        ])
    }

    private var completedToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "completed",
            "jti": "jti-completed", "exp": 2_000_000,
        ])
    }

    /// Race the post-completion refresh against a sibling
    /// `refresh()` 20 times. Across runs every observed
    /// `X-Refresh-Token` request header must be unique — proves
    /// no hop reused a token a sibling already spent.
    ///
    /// Actor scheduling is cooperative, so a precondition
    /// violation in `refreshAfterStepUp` (an `await` between
    /// drain and `startRefresh`) surfaces non-deterministically.
    /// Multiple runs catch a regression reliably without
    /// slowing CI noticeably.
    func test_postCompletion_concurrentRefresh_neverReusesRefreshToken() async throws {
        for run in 0..<20 {
            let domain = "stepup-inflight-\(run)-\(UUID().uuidString.lowercased()).example"
            let baseURL = URL(string: "https://\(domain)")!
            let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
            try await fixture.prePopulate() // refresh-v1

            fixture.http.install(
                path: "/v1/session/stepup/request",
                response: .json(["status": "continue", "challenge_token": otpToken])
            )
            fixture.http.install(
                path: "/v1/session/otp/check",
                response: .json(["challenge_token": completedToken])
            )
            // Sequence so a buggy double-spend takes refresh-v1
            // twice and the (refresh-v2, refresh-v3) rotations
            // become observable in the request log.
            fixture.http.installSequence(
                path: "/v1/session/refresh",
                responses: (1...4).map { i in
                    .json(
                        ["access_token": scopedJWT,
                         "expires_at": Int(clock().timeIntervalSince1970) + 3600],
                        headers: [HTTPHeader.refreshToken: "refresh-v\(i + 1)"]
                    )
                }
            )

            let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")

            let submit = Task {
                try await fixture.client.submitStepUpOTP(challenge, code: "x")
            }
            async let sibling = fixture.client.refresh()

            _ = try await submit.value
            // The sibling can throw on a legitimate race (e.g.
            // post-bump epoch mismatch). We only care that
            // whatever ran on the wire didn't reuse a token.
            _ = try? await sibling

            let sentTokens = fixture.http
                .requests(forPath: "/v1/session/refresh")
                .compactMap { $0.value(forHTTPHeaderField: HTTPHeader.refreshToken) }

            XCTAssertEqual(
                Set(sentTokens).count, sentTokens.count,
                "run \(run): /refresh must never reuse a refresh token — got \(sentTokens)"
            )
        }
    }
}

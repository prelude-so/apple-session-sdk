import Foundation
import XCTest
@testable import PreludeSession

/// Pins the cross-cutting transport headers every outgoing
/// request must carry. Drives the production `buildRequest` path
/// through a real round trip and inspects what landed on the
/// stub.
///
/// `User-Agent` includes the SDK version + platform/OS so backend
/// telemetry can attribute traffic without the host app having to
/// surrender its own UA. `Content-Type` is set on POSTs.
/// `Accept` is `application/json` everywhere.
///
/// TLS pinning + HTTP/2 / keep-alive are not testable in-process
/// without a real server; see the regression checklist on the
/// release ticket for the manual integration-test step.
final class TransportHeadersTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "transport-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil
        baseURL = nil
        clock = nil
        super.tearDown()
    }

    // MARK: - User-Agent

    /// Format: `Prelude/<version> (Apple; <platform> <os version>)`.
    /// Pin both the SDK identifier and the version literal so a
    /// release tooling miss (forgetting to bump the version when
    /// tagging) trips the test instead of shipping silently.
    func test_userAgent_isAttached_andCarriesSDKVersion() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )

        let recorded = fixture.http.requests(forPath: "/v1/session/otp")
        let userAgent = try XCTUnwrap(
            recorded.first?.value(forHTTPHeaderField: HTTPHeader.userAgent)
        )

        XCTAssertTrue(
            userAgent.hasPrefix("Prelude/"),
            "User-Agent must start with `Prelude/`; got \(userAgent)"
        )
        XCTAssertTrue(
            userAgent.contains(PreludeSessionSDK.version),
            "User-Agent must include the SDK version literal; got \(userAgent)"
        )
        XCTAssertTrue(
            userAgent.contains("(Apple;"),
            "User-Agent must declare the Apple platform family; got \(userAgent)"
        )
    }

    /// SDK version is exposed publicly so apps can surface it in
    /// their own diagnostics. Pinning the format keeps the
    /// public API contract honest under release-tool churn.
    func test_publicSDKVersion_isNonEmptySemverLike() {
        let version = PreludeSessionSDK.version
        XCTAssertFalse(version.isEmpty, "SDK version must not be empty")
        XCTAssertTrue(
            version.split(separator: ".").count >= 2,
            "SDK version should look semver-ish (`MAJOR.MINOR[.PATCH]`); got \(version)"
        )
    }

    // MARK: - Content-Type / Accept

    /// POSTs that carry a body must declare `application/json`.
    /// Sample one of the body-bearing endpoints; the header is
    /// applied centrally in ``_Impl/buildRequest(path:method:)``,
    /// so one POST is sufficient pinning for all of them.
    func test_postsWithBody_carryJSONContentType() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )

        let recorded = fixture.http.requests(forPath: "/v1/session/otp")
        XCTAssertEqual(
            recorded.first?.value(forHTTPHeaderField: HTTPHeader.contentType),
            "application/json"
        )
    }

    /// `Accept` is set on every request — POST and GET alike — so
    /// the server can negotiate the JSON response shape without
    /// inspecting the method. Cheap pin against a stray refactor
    /// dropping it on a specific verb.
    func test_allRequests_carryJSONAccept() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/password/compliancy",
            response: .json([
                "min_length": 8,
                "max_length": 64,
                "uppercase": 1,
                "lowercase": 1,
                "numbers": 1,
                "symbols": 0,
            ])
        )

        // POST
        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )
        let post = fixture.http.requests(forPath: "/v1/session/otp").first
        XCTAssertEqual(post?.value(forHTTPHeaderField: HTTPHeader.accept), "application/json")

        // GET
        _ = try await fixture.client.passwordCompliancy()
        let get = fixture.http.requests(forPath: "/v1/session/password/compliancy").first
        XCTAssertEqual(get?.value(forHTTPHeaderField: HTTPHeader.accept), "application/json")
    }
}

import Foundation
@testable import PreludeAuth
import XCTest

/// `metadata` rides on `POST /stepup/request` only when the
/// caller passes a non-empty dictionary. Default-nil callers must
/// keep the prior wire shape: no key on the body, no value-less
/// `metadata: null`.
final class RequestStepUpMetadataTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "stepup-meta-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private var challengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1",
            "current_step": "verify_email",
            "jti": "jti-otp",
            "exp": 2_000_000,
        ])
    }

    private func makeFixture() async throws -> Fixture {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": challengeToken])
        )
        return fixture
    }

    private func body(of req: URLRequest) throws -> [String: Any] {
        let raw = try XCTUnwrap(req.httpBody)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
    }

    func test_metadata_omittedByDefault() async throws {
        let fixture = try await makeFixture()
        _ = try await fixture.client.requestStepUp(scope: "prld:pwd:write")

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/stepup/request").first)
        let json = try body(of: req)
        XCTAssertEqual(json["scope"] as? String, "prld:pwd:write")
        XCTAssertNil(json["metadata"], "default-nil metadata must not appear on the wire")
    }

    func test_metadata_passedThroughVerbatim() async throws {
        let fixture = try await makeFixture()
        _ = try await fixture.client.requestStepUp(
            scope: "prld:pwd:write",
            metadata: ["reason": "settings", "channel": "ios"]
        )

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/stepup/request").first)
        let json = try body(of: req)
        let metadata = try XCTUnwrap(json["metadata"] as? [String: String])
        XCTAssertEqual(metadata, ["reason": "settings", "channel": "ios"])
    }
}

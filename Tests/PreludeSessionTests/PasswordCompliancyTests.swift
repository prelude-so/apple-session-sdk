import Foundation
import XCTest
@testable import PreludeSession

final class PasswordCompliancyTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "pwd-compliancy-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    func test_passwordCompliancy_decodesAllFields() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

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

        let compliancy = try await fixture.client.passwordCompliancy()

        XCTAssertEqual(
            compliancy,
            PreludePasswordCompliancy(
                minLength: 8,
                maxLength: 64,
                uppercase: 1,
                lowercase: 1,
                numbers: 1,
                symbols: 0
            )
        )

        // GET, not POST — the default request builder posts.
        let recorded = fixture.http.requests(forPath: "/v1/session/password/compliancy")
        XCTAssertEqual(recorded.count, 1)
        XCTAssertEqual(recorded.first?.httpMethod, "GET")

        // No body, no Content-Type. Strict proxies reject a
        // Content-Type on a bodyless request.
        XCTAssertNil(recorded.first?.value(forHTTPHeaderField: "Content-Type"))
        XCTAssertEqual(recorded.first?.value(forHTTPHeaderField: "Accept"), "application/json")
    }
}

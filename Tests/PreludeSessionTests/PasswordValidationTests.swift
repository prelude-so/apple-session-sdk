import Foundation
import XCTest
@testable import PreludeSession

final class PasswordValidationTests: XCTestCase {
    private let standardRules = PreludePasswordCompliancy(
        minLength: 8,
        maxLength: 64,
        uppercase: 1,
        lowercase: 1,
        numbers: 1,
        symbols: 1
    )

    // MARK: - Pure classification

    func test_validate_passwordMeetsAllRules_isValid() {
        let result = PreludeSessionClient.validate(
            password: "Abcdef1!",
            against: standardRules
        )

        XCTAssertTrue(result.valid)
        XCTAssertEqual(result.results.count, 6)
        for entry in result.results {
            XCTAssertTrue(entry.valid, "criterion \(entry.criterion) should pass")
        }
    }

    func test_validate_tooShort_failsMinLengthOnly() {
        let result = PreludeSessionClient.validate(
            password: "Ab1!",
            against: standardRules
        )

        XCTAssertFalse(result.valid)
        let byCriterion = Dictionary(
            uniqueKeysWithValues: result.results.map { ($0.criterion, $0) }
        )
        XCTAssertEqual(byCriterion[.minLength]?.valid, false)
        XCTAssertEqual(byCriterion[.minLength]?.actual, 4)
        XCTAssertEqual(byCriterion[.minLength]?.expected, 8)
        XCTAssertEqual(byCriterion[.maxLength]?.valid, true)
    }

    func test_validate_maxLengthZero_treatedAsNoUpperBound() {
        let rules = PreludePasswordCompliancy(
            minLength: 1, maxLength: 0,
            uppercase: 0, lowercase: 0, numbers: 0, symbols: 0
        )

        let result = PreludeSessionClient.validate(
            password: String(repeating: "a", count: 10_000),
            against: rules
        )

        let max = result.results.first { $0.criterion == .maxLength }
        XCTAssertEqual(max?.valid, true)
    }

    func test_validate_missingUppercase_failsJustUppercase() {
        let result = PreludeSessionClient.validate(
            password: "abcdef1!",
            against: standardRules
        )

        XCTAssertFalse(result.valid)
        for entry in result.results where entry.criterion != .uppercase {
            XCTAssertTrue(entry.valid, "\(entry.criterion) should have passed")
        }
        let upper = result.results.first { $0.criterion == .uppercase }
        XCTAssertEqual(upper?.actual, 0)
        XCTAssertEqual(upper?.valid, false)
    }

    /// Counting iterates Unicode code points, not grapheme clusters,
    /// so multi-scalar clusters (flag emojis, ZWJ sequences) decompose
    /// to their underlying scalars.
    func test_validate_countsUnicodeCodePoints_notGraphemeClusters() {
        let flag = "🇫🇷"  // 2 scalars (regional-indicator pair), 1 grapheme cluster
        XCTAssertEqual(flag.count, 1)
        XCTAssertEqual(flag.unicodeScalars.count, 2)

        let rules = PreludePasswordCompliancy(
            minLength: 2, maxLength: 0,
            uppercase: 0, lowercase: 0, numbers: 0, symbols: 2
        )
        let result = PreludeSessionClient.validate(password: flag, against: rules)

        let min = result.results.first { $0.criterion == .minLength }
        XCTAssertEqual(min?.actual, 2)
        XCTAssertEqual(min?.valid, true)
    }

    /// Unicode letters outside ASCII land in uppercase / lowercase,
    /// not symbols.
    func test_validate_classifiesNonASCIILetters() {
        let rules = PreludePasswordCompliancy(
            minLength: 1, maxLength: 0,
            uppercase: 0, lowercase: 0, numbers: 0, symbols: 0
        )

        let result = PreludeSessionClient.validate(
            password: "Αβγ",  // Greek capital alpha, small beta, small gamma
            against: rules
        )

        let upper = result.results.first { $0.criterion == .uppercase }
        let lower = result.results.first { $0.criterion == .lowercase }
        let symbols = result.results.first { $0.criterion == .symbols }
        XCTAssertEqual(upper?.actual, 1)
        XCTAssertEqual(lower?.actual, 2)
        XCTAssertEqual(symbols?.actual, 0)
    }

    // MARK: - End-to-end through the HTTP stack

    func test_validatePassword_fetchesCompliancy_andAppliesIt() async throws {
        let domain = "pwd-val-test-\(UUID().uuidString.lowercased()).example"
        let baseURL = URL(string: "https://\(domain)")!
        let clock: NowProvider = { Date(timeIntervalSince1970: 1_000_000) }
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        fixture.http.install(
            path: "/v1/session/password/compliancy",
            response: .json([
                "min_length": 8,
                "max_length": 0,
                "uppercase": 0,
                "lowercase": 0,
                "numbers": 0,
                "symbols": 0,
            ])
        )

        let result = try await fixture.client.validatePassword("longenoughpw")

        XCTAssertTrue(result.valid)
        XCTAssertEqual(
            result.results.first { $0.criterion == .minLength }?.actual,
            12
        )
    }
}

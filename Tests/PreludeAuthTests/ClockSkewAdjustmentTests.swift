@testable import PreludeAuth
import XCTest

/// ``PreludeAuthClient/adjustedLocalExpiresAt(serverExpiresAt:timeDiffSec:)``
/// must apply skew symmetrically and never overestimate the stored
/// expiry. `floor` (in `Double` space) is required: `Int(_:)` rounds
/// toward zero, which equals `floor` only for non-negative inputs,
/// so a sub-second negative skew would otherwise round up and let
/// the stored expiry exceed the exact adjusted value.
final class ClockSkewAdjustmentTests: XCTestCase {
    private let server = 1_700_000_000

    // MARK: - Integer skews round-trip exactly

    func testZeroSkewIsNoOp() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: 0),
            server
        )
    }

    func testPositiveIntegerSkewIsApplied() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: 2),
            server + 2
        )
    }

    func testNegativeIntegerSkewIsApplied() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: -2),
            server - 2
        )
    }

    // MARK: - Sub-second skews

    func testSubSecondPositiveSkewFloorsToServerExpiresAt() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: 0.5),
            server
        )
    }

    func testSubSecondNegativeSkewIsApplied() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: -0.5),
            server - 1
        )
    }

    func testFractionalPositiveSkewIsFloored() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: 1.9),
            server + 1
        )
    }

    func testFractionalNegativeSkewIsFloored() {
        XCTAssertEqual(
            PreludeAuthClient.adjustedLocalExpiresAt(serverExpiresAt: server, timeDiffSec: -1.9),
            server - 2
        )
    }

    // MARK: - Safety invariant

    func testResultNeverOverestimatesExactAdjustedExpiration() {
        // The stored Int expiration must be at or below the exact
        // Double value regardless of skew sign or magnitude.
        for skew in [-5.0, -2.5, -0.9, -0.1, 0.0, 0.1, 0.9, 2.5, 5.0] {
            let stored = PreludeAuthClient.adjustedLocalExpiresAt(
                serverExpiresAt: server,
                timeDiffSec: skew
            )
            let exact = Double(server) + skew
            XCTAssertLessThanOrEqual(
                Double(stored),
                exact,
                "stored expiration for skew=\(skew) exceeded the exact adjusted expiration"
            )
        }
    }
}

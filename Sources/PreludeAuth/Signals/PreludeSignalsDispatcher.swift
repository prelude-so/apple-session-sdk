import Foundation

/// Pluggable anti-fraud signals dispatcher.
///
/// ``PreludeAuthClient`` calls ``dispatch()`` at the start of an
/// unauthenticated login and attaches the returned `dispatch_id` to
/// the request body. Returning `nil` is a supported no-op.
public protocol PreludeSignalsDispatcher: Sendable {
    /// Return a fresh `dispatch_id`, or `nil` when signals are skipped.
    func dispatch() async throws -> String?
}

import Foundation
import Prelude

/// Forwards ``PreludeSignalsDispatcher/dispatch()`` calls into the
/// edge `Prelude` SDK's signals subsystem.
///
/// `@unchecked Sendable`: the upstream `Prelude` and `Configuration`
/// types are value-type structs without shared mutable state.
public struct PreludeSignalsAdapter: PreludeSignalsDispatcher, @unchecked Sendable {
    private let prelude: Prelude?

    /// Pass `nil` or an empty `sdkKey` for a permissive no-op — useful
    /// when the key is loaded asynchronously or signals are disabled.
    public init(
        sdkKey: String?,
        timeout: TimeInterval = 5.0
    ) {
        guard let sdkKey, !sdkKey.isEmpty else {
            prelude = nil
            return
        }
        prelude = Prelude(Configuration(sdkKey: sdkKey, timeout: timeout))
    }

    public func dispatch() async throws -> String? {
        guard let prelude else { return nil }
        return try await prelude.dispatchSignals()
    }
}

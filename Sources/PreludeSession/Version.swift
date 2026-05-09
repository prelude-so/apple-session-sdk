import Foundation

/// SDK version + transport-layer identification.
///
/// Format: `Prelude/<sdk-version> (<platform>; <os name> <os version>)`
///
/// Platform and OS version are included so server-side telemetry
/// can distinguish iOS / macOS / tvOS deployments without forcing
/// the host app to surrender its own `User-Agent`.
///
/// ``version`` is the source of truth; release tooling rewrites
/// this constant alongside the package tag.
enum PreludeSessionSDK {
    /// Semantic version of the PreludeSession package. Bumped at
    /// release time; exposed publicly so apps can include it in
    /// their own diagnostics.
    public static let version = "0.2.0"

    /// `User-Agent` value attached to every outgoing request.
    static let userAgent: String = {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        return "Prelude/\(version) (Apple; \(platformName) \(osVersion))"
    }()

    private static var platformName: String {
        #if os(iOS)
        return "iOS"
        #elseif os(macOS)
        return "macOS"
        #elseif os(tvOS)
        return "tvOS"
        #elseif os(watchOS)
        return "watchOS"
        #elseif os(visionOS)
        return "visionOS"
        #else
        return "unknown"
        #endif
    }
}

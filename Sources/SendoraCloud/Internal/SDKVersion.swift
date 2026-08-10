import Foundation

// Single source of truth for the SDK's identity (ADR-023 §3.4 / s58.221).
//
// Swift packages cannot read `Package.swift` at runtime, so this code
// constant IS the canonical version — nothing else in the package may
// hardcode the version string. It feeds both the event body
// `context.sdk` and the `X-Sendora-SDK-{Name,Version}` request headers.
// Keep this in lockstep with the `Package.swift` comment + git tag on release.
extension SendoraCloud {
    /// Canonical SDK version. The ONLY place the version string lives.
    internal static let sdkVersion = "4.19.0"

    /// Canonical SDK name, shared by the event body + request headers.
    internal static let sdkName = "sendora-ios"
}

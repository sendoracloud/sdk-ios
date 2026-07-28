// swift-tools-version: 5.9
import PackageDescription

// Published version: 4.14.0 (git tag is the SwiftPM source of truth).
// The runtime version constant lives in
// `Sources/SendoraCloud/Internal/SDKVersion.swift` — keep both in lockstep
// with the release git tag (ADR-023: no hardcoded version drift).
let package = Package(
    name: "SendoraCloud",
    platforms: [
        // iOS 15 floor (restored in s58.235). Passkeys (iOS 16, ASAuthorization-
        // PlatformPublicKeyCredentialProvider) are @available(iOS 16)-guarded so
        // they no longer force the whole package up — same treatment Live
        // Activities (iOS 16.1) already had. Everything else — deep links (incl.
        // runtime links.create()), analytics, push, auth, SSO — works on iOS 15.
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(name: "SendoraCloud", targets: ["SendoraCloud"])
    ],
    targets: [
        .target(
            name: "SendoraCloud",
            path: "Sources/SendoraCloud"
        ),
        .testTarget(
            name: "SendoraCloudTests",
            dependencies: ["SendoraCloud"],
            path: "Tests/SendoraCloudTests"
        )
    ]
)

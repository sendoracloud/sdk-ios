// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SendoraCloud",
    platforms: [
        // Bumped to iOS 16 for native passkey (ASAuthorizationPlatformPublicKeyCredentialProvider)
        // support added in 2.3.0. iOS 16 GA was Sept 2022 — well within
        // the supported runtime window for any active app.
        .iOS(.v16),
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

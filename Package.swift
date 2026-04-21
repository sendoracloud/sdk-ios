// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SendoraCloud",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
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

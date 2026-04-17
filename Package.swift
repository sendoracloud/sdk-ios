// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Sendora",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "Sendora", targets: ["Sendora"])
    ],
    targets: [
        .target(
            name: "Sendora",
            path: "Sources/Sendora"
        ),
        .testTarget(
            name: "SendoraTests",
            dependencies: ["Sendora"],
            path: "Tests/SendoraTests"
        )
    ]
)

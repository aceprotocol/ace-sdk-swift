// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "ace-sdk-swift",
    platforms: [.macOS(.v26), .iOS(.v26)],
    products: [
        .library(name: "ACE", targets: ["ACE"]),
    ],
    targets: [
        .target(name: "ACE", path: "Sources/ACE", resources: [.copy("Profiles")]),
        .executableTarget(name: "ACEQuickstart", dependencies: ["ACE"], path: "Examples/Quickstart"),
        /// The interop matrix driver (ace-spec/interop/README.md).
        .executableTarget(name: "ACEInterop", dependencies: ["ACE"], path: "Examples/Interop"),
        .testTarget(name: "ACETests", dependencies: ["ACE"], path: "Tests/ACETests", exclude: ["Fixtures"]),
    ]
)

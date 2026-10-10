// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "ace-sdk-swift",
    platforms: [.macOS(.v26), .iOS(.v26)],
    products: [
        .library(name: "ACE", targets: ["ACE"]),
        // Local interop drivers for session-core/tests (never network endpoints).
        .executable(name: "SecureInterop", targets: ["ACESecureInterop"]),
        .executable(name: "MLSInterop", targets: ["ACEMLSInterop"]),
    ],
    dependencies: [
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift", exact: "0.23.0"),
        // The source-built MLS engine (sibling checkout; run `python3 build.py --apple` there first).
        // The release pins `.package(url: "https://github.com/aceprotocol/ace-session-core.git", exact: "<version>")`.
        .package(name: "ace-session-core", path: "../session-core/bindings/swift"),
    ],
    targets: [
        .executableTarget(name: "ACEQuickstart", dependencies: ["ACE"], path: "Examples/Quickstart"),
        .target(
            name: "ACE",
            dependencies: [
                .product(name: "P256K", package: "secp256k1.swift"),
                .product(name: "ACESessionCore", package: "ace-session-core"),
            ],
            path: "Sources/ACE"
        ),
        .executableTarget(name: "ACESecureInterop", dependencies: ["ACE"], path: "Sources/ACESecureInterop"),
        .executableTarget(name: "ACEMLSInterop", dependencies: ["ACE"], path: "Sources/ACEMLSInterop"),
        .testTarget(
            name: "ACETests",
            dependencies: ["ACE"],
            path: "Tests/ACETests",
            resources: [.copy("Fixtures")]
        ),
    ]
)

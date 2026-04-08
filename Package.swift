// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ace-sdk",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "ACE", targets: ["ACE"]),
    ],
    dependencies: [
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift", exact: "0.23.0"),
    ],
    targets: [
        .target(
            name: "ACE",
            dependencies: [
                .product(name: "P256K", package: "secp256k1.swift"),
            ],
            path: "Sources/ACE"
        ),
        .testTarget(
            name: "ACETests",
            dependencies: ["ACE"],
            path: "Tests/ACETests"
        ),
    ]
)

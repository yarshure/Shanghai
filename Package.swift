// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Shanghai",
    platforms: [
        .macOS(.v11),
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "CKcp",
            type: .static,
            targets: ["CKcp"]
        ),
        .library(
            name: "Shanghai",
            targets: ["Shanghai"]
        ),
        .executable(
            name: "ShanghaiProxy",
            targets: ["ShanghaiProxy"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/yarshure/Lisao", branch: "main"),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
        .package(url: "https://github.com/awxkee/snappy.swift", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "CKcp",
            publicHeadersPath: "include"
        ),
        .target(
            name: "Shanghai",
            dependencies: [
                "CKcp",
                .product(name: "Lisao", package: "Lisao"),
                .product(name: "snappy", package: "snappy.swift"),
                .product(name: "Sodium", package: "swift-sodium"),
            ]
        ),
        .executableTarget(
            name: "ShanghaiProxy",
            dependencies: ["Shanghai"]
        ),
        .testTarget(
            name: "ShanghaiTests",
            dependencies: ["Shanghai"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

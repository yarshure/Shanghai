// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Shanghai",
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
    ],
    dependencies: [
        .package(url: "https://github.com/yarshure/Liso", branch: "main")
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
                .product(name: "Lisao", package: "Liso")
            ]
        ),
        .testTarget(
            name: "ShanghaiTests",
            dependencies: ["Shanghai"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

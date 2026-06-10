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
        // Hub-side / sidecar UDP<->KCP forwarder. The only product a
        // Linux hub needs: `swift build --product kcpfwd`. (ShanghaiProxy
        // imports Network and stays Apple-only.)
        .executable(
            name: "kcpfwd",
            targets: ["kcpfwd"]
        ),
    ],
    dependencies: [
        // NOTE: Lisao (was an unused import) and swift-sodium (only ever
        // produced random nonce bytes, replaced by SystemRandomNumberGenerator)
        // were dropped to keep the Linux build dependency-free. AES-CFB and
        // PBKDF2-SHA1 live in CKcp/shanghai_crypt.c — libsodium provides
        // neither, so it could not have covered the kcptun wire crypt anyway.
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
                // snappy.swift wraps an xcframework — Apple platforms only.
                // KcpSnappyFramedCodec degrades to throwing stubs elsewhere.
                .product(
                    name: "snappy",
                    package: "snappy.swift",
                    condition: .when(platforms: [.macOS, .iOS, .macCatalyst, .tvOS, .watchOS, .visionOS])
                ),
            ]
        ),
        .executableTarget(
            name: "ShanghaiProxy",
            dependencies: ["Shanghai"]
        ),
        .executableTarget(
            name: "kcpfwd",
            dependencies: ["Shanghai"]
        ),
        .testTarget(
            name: "ShanghaiTests",
            dependencies: ["Shanghai"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

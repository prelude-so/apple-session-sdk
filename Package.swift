// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "PreludeSession",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "PreludeSession",
            targets: ["PreludeSession"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/prelude-so/apple-sdk.git",
            exact: "0.5.1"
        ),
    ],
    targets: [
        .target(
            name: "PreludeSession",
            dependencies: [
                .product(name: "Prelude", package: "apple-sdk"),
            ]
        ),
    ]
)

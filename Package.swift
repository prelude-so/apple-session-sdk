// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "PreludeAuth",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "PreludeAuth",
            targets: ["PreludeAuth"]
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
            name: "PreludeAuth",
            dependencies: [
                .product(name: "Prelude", package: "apple-sdk"),
            ]
        ),
    ]
)

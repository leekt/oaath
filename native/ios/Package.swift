// swift-tools-version:5.10
// EXPERIMENTAL PREVIEW — owner-phone iOS approval app for the OAAth relay.
// Not part of the fixed npm release group and never published to npm.
import PackageDescription

let package = Package(
    name: "oaath-owner-phone",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "OwnerPhone", targets: ["OwnerPhone"])
    ],
    targets: [
        .target(name: "OwnerPhone"),
        .testTarget(name: "OwnerPhoneTests", dependencies: ["OwnerPhone"])
    ]
)

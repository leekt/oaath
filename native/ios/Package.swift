// swift-tools-version:5.10
// EXPERIMENTAL PREVIEW — owner-phone iOS approval app for the OAAth relay.
// Not part of the fixed npm release group and never published to npm.
//
// OwnerPhone is the reviewed wire/consent library; OwnerPhoneDemo is the demo
// app's wiring (pairing, transport, code delivery, screens) consumed by the
// runnable Xcode app in ./Demo.
import PackageDescription

let package = Package(
    name: "oaath-owner-phone",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "OwnerPhone", targets: ["OwnerPhone"]),
        .library(name: "OwnerPhoneDemo", targets: ["OwnerPhoneDemo"])
    ],
    targets: [
        .target(name: "OwnerPhone"),
        .target(name: "OwnerPhoneDemo", dependencies: ["OwnerPhone"]),
        .testTarget(name: "OwnerPhoneTests", dependencies: ["OwnerPhone", "OwnerPhoneDemo"])
    ]
)

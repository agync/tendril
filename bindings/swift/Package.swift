// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "Tendril",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(name: "Tendril", targets: ["Tendril"]),
  ],
  targets: [
    .target(
      name: "CTendril",
      path: "Sources/CTendril",
      publicHeadersPath: "include",
      linkerSettings: [
        .linkedLibrary("tendril_ffi"),
        .unsafeFlags([
          "-L../../target/release",
          "-L../../target/debug",
        ]),
      ]
    ),
    .target(
      name: "Tendril",
      dependencies: ["CTendril"],
      path: "Sources/Tendril"
    ),
    .testTarget(
      name: "TendrilTests",
      dependencies: ["Tendril"],
      path: "Tests/TendrilTests"
    ),
  ]
)

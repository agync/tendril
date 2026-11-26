// swift-tools-version: 5.9
import Foundation
import PackageDescription

let tendrilReleaseVersion = "0.1.0"
let tendrilXCFrameworkChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

let useLocalFfi = ProcessInfo.processInfo.environment["TENDRIL_LOCAL_FFI"] == "1"

let cTendrilTarget: Target
if useLocalFfi {
  cTendrilTarget = .target(
    name: "CTendril",
    path: "bindings/swift/Sources/CTendril",
    publicHeadersPath: "include",
    linkerSettings: [
      .linkedLibrary("tendril_ffi"),
      .unsafeFlags([
        "-Ltarget/release",
        "-Ltarget/debug",
      ]),
    ]
  )
} else {
  cTendrilTarget = .binaryTarget(
    name: "CTendril",
    url: "https://github.com/agync/tendril/releases/download/v\(tendrilReleaseVersion)/TendrilFFI.xcframework-\(tendrilReleaseVersion).zip",
    checksum: tendrilXCFrameworkChecksum
  )
}

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
    cTendrilTarget,
    .target(
      name: "Tendril",
      dependencies: ["CTendril"],
      path: "bindings/swift/Sources/Tendril",
      linkerSettings: [
        .linkedFramework("CoreFoundation"),
        .linkedFramework("Network"),
        .linkedFramework("Security"),
        .linkedFramework("SystemConfiguration"),
        .linkedLibrary("resolv"),
      ]
    ),
    .testTarget(
      name: "TendrilTests",
      dependencies: ["Tendril", "CTendril"],
      path: "bindings/swift/Tests/TendrilTests"
    ),
  ]
)

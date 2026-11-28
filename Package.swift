// swift-tools-version: 5.9
import Foundation
import PackageDescription

let tendrilReleaseVersion = "0.2.1"
let tendrilXCFrameworkChecksum = "3cc50301dea3f30476f7acfc0b07dd516bb2e94fd529a330725a00f6c25dc020"

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

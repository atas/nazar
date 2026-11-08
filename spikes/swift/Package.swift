// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "NazarSpikes",
    platforms: [.macOS("26.0")],
    targets: [
        .systemLibrary(name: "CSpikeCore", path: "Sources/CSpikeCore"),
        .executableTarget(
            name: "S11App", dependencies: ["CSpikeCore"],
            linkerSettings: [.linkedFramework("CoreFoundation"), .linkedFramework("Security"),
                             .linkedFramework("LocalAuthentication"), .linkedFramework("AppKit")]),
        .executableTarget(
            name: "S1Enclave",
            linkerSettings: [.linkedFramework("LocalAuthentication"), .linkedFramework("Security"),
                             .linkedFramework("AppKit")]),
        .executableTarget(name: "S5Other", linkerSettings: [.linkedFramework("Security")]),
        .executableTarget(
            name: "S3Callers",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("AppKit")]),
        .executableTarget(
            name: "S4Confirm",
            linkerSettings: [.linkedFramework("AppKit"), .linkedFramework("Carbon")]),
    ],
    swiftLanguageModes: [.v5]
)

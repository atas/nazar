// swift-tools-version:6.0
// nazar's Swift side (spec 4.7). NazarPlatform implements the Go core's
// Platform, Vault and audit.Sink contracts; CNazarBridge is the C ABI both
// sides compile against. The executables that link a Go c-archive
// (NazarConformanceHost, NazarAgent, NazarSmokeHost) need `make archives`
// first (../build). NazarUI is Nazar UI.app's library and is linked into
// nothing that touches keys (Milestone 6).
import PackageDescription

let package = Package(
    name: "Nazar",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "NazarPlatform", targets: ["NazarPlatform"]),
        .library(name: "NazarUI", targets: ["NazarUI"]),
    ],
    targets: [
        .target(name: "CNazarBridge", path: "Sources/CNazarBridge"),
        .target(
            name: "NazarPlatform", dependencies: ["CNazarBridge"],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication"),
                             .linkedFramework("AppKit"), .linkedFramework("CryptoKit"),
                             .linkedFramework("Carbon")]),
        .testTarget(name: "NazarPlatformTests", dependencies: ["NazarPlatform", "CNazarBridge"]),
        // The Nazar window (spec 6.1): a thin client of the nazar CLI. No Go
        // core, no platform layer, no sockets.
        .target(name: "NazarUI"),
        .testTarget(name: "NazarUITests", dependencies: ["NazarUI"], exclude: ["Fixtures"]),
        // Nazar UI.app's executable (Milestone 6): NazarUI and nothing else.
        // `make ui`.
        .executableTarget(name: "NazarUIApp", dependencies: ["NazarUI"]),
        // nazar-agent.app's executable (Milestone 6): links
        // build/libnazar-core.a, never NazarUI. `make agent`.
        .systemLibrary(name: "CNazarCore", path: "Sources/CNazarCore"),
        .executableTarget(
            name: "NazarAgent", dependencies: ["NazarPlatform", "CNazarBridge", "CNazarCore"],
            linkerSettings: [.linkedFramework("CoreFoundation"), .linkedFramework("Security")]),
        // The real core on the real platform with scripted gates: `make integration-swift`.
        .executableTarget(
            name: "NazarSmokeHost", dependencies: ["NazarPlatform", "CNazarBridge", "CNazarCore"],
            linkerSettings: [.linkedFramework("CoreFoundation"), .linkedFramework("Security")]),
        // A small C program the exec tests run: execs the rest of
        // its command line on each line of stdin. Built next to the test
        // bundle and the conformance host; never in a bundle.
        .executableTarget(name: "NazarExecProbe", path: "Sources/NazarExecProbe"),
        // Links build/libnazar-conformance.a: `make conformance`.
        .systemLibrary(name: "CNazarConformance", path: "Sources/CNazarConformance"),
        .executableTarget(
            name: "NazarConformanceHost", dependencies: ["NazarPlatform", "CNazarBridge", "CNazarConformance"],
            linkerSettings: [.linkedFramework("CoreFoundation"), .linkedFramework("Security")]),
    ],
    swiftLanguageModes: [.v5]
)

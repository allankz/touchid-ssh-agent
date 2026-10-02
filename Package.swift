// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "TouchIDSSHAgent",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "touchid-ssh-agent", targets: ["touchid-ssh-agent"]),
    ],
    targets: [
        .target(
            name: "TouchIDSSHCore",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "touchid-ssh-agent",
            dependencies: ["TouchIDSSHCore"]
        ),
        // XCTest and swift-testing are unavailable with Command Line Tools only,
        // so the test suite is a plain executable: `swift run touchid-ssh-agent-selftest`.
        .executableTarget(
            name: "touchid-ssh-agent-selftest",
            dependencies: ["TouchIDSSHCore"],
            path: "Tests/SelfTest"
        ),
    ]
)

import Foundation

/// Per-user launchd job that keeps the agent running in the GUI session, where
/// the Touch ID dialog can be shown.
public enum LaunchAgent {
    public static let label = "local.touchid-ssh-agent"

    public static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static var domain: String { "gui/\(getuid())" }

    public static func plist(executable: String, paths: AgentPaths) throws -> Data {
        var plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable, "agent"],
            "RunAtLoad": true,
            // Restart after crashes, not after a clean exit (e.g. another agent
            // already serving the socket), which would otherwise loop forever.
            "KeepAlive": ["SuccessfulExit": false],
            "ProcessType": "Interactive",
            "StandardErrorPath": paths.directory.appendingPathComponent("agent.stderr.log").path,
        ]
        if !paths.isDefault {
            plist["EnvironmentVariables"] = [AgentPaths.environmentVariable: paths.directory.path]
        }
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }

    /// Writes the plist and (re)starts the job.
    public static func install(executable: String, paths: AgentPaths) throws {
        try paths.ensureDirectory()
        let directory = plistURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try plist(executable: executable, paths: paths).write(to: plistURL, options: .atomic)
        _ = launchctl(["bootout", "\(domain)/\(label)"])
        let result = launchctl(["bootstrap", domain, plistURL.path])
        guard result.status == 0 else {
            throw LaunchAgentError.launchctl(result.output)
        }
        // macOS 26 may leave a freshly bootstrapped RunAtLoad job as a pending
        // "speculative" spawn that never runs; start it explicitly.
        let started = launchctl(["kickstart", "\(domain)/\(label)"])
        guard started.status == 0 else {
            throw LaunchAgentError.launchctl(started.output)
        }
    }

    public static func uninstall() throws {
        _ = launchctl(["bootout", "\(domain)/\(label)"])
        if FileManager.default.fileExists(atPath: plistURL.path) {
            try FileManager.default.removeItem(at: plistURL)
        }
    }

    public static var isLoaded: Bool {
        launchctl(["print", "\(domain)/\(label)"]).status == 0
    }

    static func launchctl(_ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (-1, "\(error)")
        }
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: output, as: UTF8.self))
    }
}

public enum LaunchAgentError: Error, CustomStringConvertible {
    case launchctl(String)

    public var description: String {
        switch self {
        case .launchctl(let output): return "launchctl failed: \(output)"
        }
    }
}

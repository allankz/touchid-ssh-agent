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
        do {
            let result = try Command.run("/bin/launchctl", arguments)
            return (result.status, result.stdoutText + result.stderrText)
        } catch {
            return (-1, "\(error)")
        }
    }
}

/// Starts the job behind one temporary grant. Each grant gets its own launchd
/// label in the GUI session (where Touch ID can be shown), with RunAtLoad,
/// LaunchOnlyOnce and no KeepAlive: when the job ends, nothing restarts it.
/// The plist lives in the grant directory, never in ~/Library/LaunchAgents, so
/// logout and reboot do not bring it back either.
public enum AccessLauncher {
    public static let labelPrefix = "local.touchid-ssh-agent.access."
    /// `process` starts the job as a detached process instead of under launchd.
    /// For the automated tests only.
    public static let modeVariable = "TOUCHID_SSH_AGENT_ACCESS_LAUNCH"

    public static var usesLaunchd: Bool {
        ProcessInfo.processInfo.environment[modeVariable] != "process"
    }

    /// `local.touchid-ssh-agent.access.<data-directory hash>.<grant-id>`: the
    /// hash keeps grants of different data directories apart.
    public static func label(paths: AgentPaths, grantId: String) -> String {
        labelPrefix + dataDirectoryTag(paths) + "." + grantId
    }

    static func dataDirectoryTag(_ paths: AgentPaths) -> String {
        String(AccessRequest.digest(Data(paths.directory.path.utf8)).prefix(8))
    }

    public static func plist(executable: String, paths: AgentPaths, directory: GrantDirectory,
                             digest: String, label: String) throws -> Data {
        var environment = [AgentPaths.environmentVariable: paths.directory.path]
        if let timeout = ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_PROMPT_TIMEOUT"] {
            environment["TOUCHID_SSH_AGENT_PROMPT_TIMEOUT"] = timeout
        }
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable, "access-job", directory.url.path, digest],
            "RunAtLoad": true,
            "LaunchOnlyOnce": true,
            "KeepAlive": false,
            "ProcessType": "Interactive",
            "EnvironmentVariables": environment,
            "StandardOutPath": "/dev/null",
            "StandardErrorPath": paths.directory.appendingPathComponent("access.stderr.log").path,
        ]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }

    /// Starts the job. Under launchd, returns nil (the job records its own
    /// process identity); in process mode, returns the child's pid.
    @discardableResult
    public static func start(executable: String, paths: AgentPaths, directory: GrantDirectory,
                             digest: String, label: String) throws -> pid_t? {
        guard usesLaunchd else {
            return try spawnDetached(executable, ["access-job", directory.url.path, digest], paths: paths)
        }
        try SecureFile.writeAtomically(try plist(executable: executable, paths: paths, directory: directory,
                                                 digest: digest, label: label), to: directory.plist, mode: 0o600)
        let result = LaunchAgent.launchctl(["bootstrap", LaunchAgent.domain, directory.plist.path])
        guard result.status == 0 else { throw LaunchAgentError.launchctl(result.output) }
        // As for the agent: macOS 26 may leave a bootstrapped job pending.
        _ = LaunchAgent.launchctl(["kickstart", "\(LaunchAgent.domain)/\(label)"])
        return nil
    }

    /// Unloads a grant's job; stops it first if it still runs.
    public static func bootout(label: String) {
        guard label.hasPrefix(labelPrefix) else { return }
        _ = LaunchAgent.launchctl(["bootout", "\(LaunchAgent.domain)/\(label)"])
    }

    public static func isLoaded(label: String) -> Bool {
        LaunchAgent.launchctl(["print", "\(LaunchAgent.domain)/\(label)"]).status == 0
    }

    /// Labels of this data directory's grant jobs that launchd still lists.
    public static func loadedLabels(paths: AgentPaths) -> [(label: String, running: Bool)] {
        let prefix = labelPrefix + dataDirectoryTag(paths) + "."
        let listing = LaunchAgent.launchctl(["list"]).output
        return listing.split(whereSeparator: \.isNewline).compactMap { line in
            let fields = line.split(separator: "\t")
            guard fields.count == 3, fields[2].hasPrefix(prefix) else { return nil }
            return (String(fields[2]), fields[0] != "-")
        }
    }

    static func spawnDetached(_ executable: String, _ arguments: [String], paths: AgentPaths) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)
        let errorLog = paths.directory.appendingPathComponent("access.stderr.log").path
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, errorLog, O_WRONLY | O_CREAT | O_APPEND, 0o600)
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // The job starts with default signal handling, whatever the CLI ignored.
        var defaults = sigset_t()
        sigemptyset(&defaults)
        for signalNumber in [SIGINT, SIGTERM, SIGHUP, SIGPIPE] { sigaddset(&defaults, signalNumber) }
        posix_spawnattr_setsigdefault(&attributes, &defaults)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF))
        let environment = ProcessInfo.processInfo.environment
            .merging([AgentPaths.environmentVariable: paths.directory.path]) { $1 }
            .map { "\($0.key)=\($0.value)" }
        var argv = ([executable] + arguments).map { strdup($0) } + [nil]
        var envp = environment.map { strdup($0) } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, executable, &actions, &attributes, &argv, &envp)
        guard spawned == 0 else { throw CommandError.launchFailed(executable, String(cString: strerror(spawned))) }
        return pid
    }
}

/// Proves that a server accepts a certificate without running anything there:
/// `ssh -N` opens no session (so no shell, command, subsystem or forced
/// command), and the connection is closed as soon as ssh reports that the
/// certificate's key was accepted and authentication completed.
public enum CertificateLoginCheck {
    public enum Outcome: Equatable {
        case ok
        case failed(String)
    }

    public static func run(configFile: URL, alias: String, keyFingerprint: String, timeout: TimeInterval = 25) -> Outcome {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: RemoteKeys.ssh)
        process.arguments = ["-F", configFile.path, "-v", "-N", "-T", alias]
        let errors = Pipe()
        process.standardError = errors
        process.standardOutput = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice

        let lock = NSLock()
        var pending = Data()
        var accepted = false
        var outcome: Outcome?
        var lastError = ""
        var lastLine = ""
        let done = DispatchSemaphore(value: 0)
        errors.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            lock.lock()
            defer { lock.unlock() }
            guard !chunk.isEmpty else { return }
            // Split on bytes: ssh ends its log lines with \r\n, which Swift treats as one Character.
            pending.append(chunk)
            while let newline = pending.firstIndex(of: UInt8(ascii: "\n")) {
                let line = String(decoding: pending[pending.startIndex..<newline], as: UTF8.self)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
                pending = Data(pending[(newline + 1)...])
                lastLine = line
                if line.contains("Server accepts key:"), line.contains("ED25519-CERT"), line.contains(keyFingerprint) {
                    accepted = true
                }
                if line.hasPrefix("Authenticated to "), outcome == nil {
                    outcome = accepted ? .ok : .failed("authenticated with something other than the certificate")
                    done.signal()
                } else if !line.hasPrefix("debug"), !line.isEmpty {
                    lastError = line
                }
            }
        }
        process.terminationHandler = { _ in done.signal() }
        do {
            try process.run()
        } catch {
            return .failed("could not run ssh: \(error)")
        }
        let finished = done.wait(timeout: .now() + timeout) == .success
        if process.isRunning {
            process.terminate()
            // ssh keeps SIGTERM ignored when its parent ignores it (as `access`
            // does while it handles Ctrl-C itself), so fall back to SIGKILL.
            let grace = Date().addingTimeInterval(2)
            while process.isRunning, Date() < grace { usleep(50_000) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
        process.waitUntilExit()
        errors.fileHandleForReading.readabilityHandler = nil
        lock.lock()
        defer { lock.unlock() }
        if let outcome { return outcome }
        if !finished {
            return .failed("no answer within \(Int(timeout)) s (last: \(DisplayText.sanitize(lastLine, maxLength: 160)))")
        }
        let reason = DisplayText.sanitize(lastError.isEmpty ? "ssh exited with status \(process.terminationStatus)" : lastError,
                                          maxLength: 200)
        return .failed(reason)
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

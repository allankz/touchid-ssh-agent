import Darwin
import Foundation

public struct CommandResult {
    public let status: Int32
    public let stdout: Data
    public let stderr: Data

    public var stdoutText: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrText: String { String(decoding: stderr, as: UTF8.self) }
    public var succeeded: Bool { status == 0 }
}

public enum CommandError: Error, CustomStringConvertible {
    case notFound(String)
    case launchFailed(String, String)

    public var description: String {
        switch self {
        case .notFound(let name): return "\(name) was not found."
        case .launchFailed(let name, let reason): return "Could not run \(name): \(reason)"
        }
    }
}

/// Runs external tools (ssh, ssh-keygen, age, launchctl) without a shell.
public enum Command {
    /// Directories searched in addition to $PATH. launchd jobs get a minimal
    /// PATH, and Homebrew installs into /opt/homebrew or /usr/local.
    public static let extraSearchPaths = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]

    public static func find(_ name: String) -> String? {
        let pathDirectories = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":").map(String.init)
        for directory in pathDirectories + extraSearchPaths {
            let candidate = (directory as NSString).appendingPathComponent(name)
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    /// - Parameters:
    ///   - stdin: bytes written to the child's stdin, then closed. When nil the
    ///     child inherits this process's stdin (needed for interactive prompts).
    ///   - inheritStderr: pass stderr through to the terminal instead of
    ///     capturing it, so the user sees prompts and errors from ssh.
    ///   - removingEnvironment: variables removed from the child's environment.
    @discardableResult
    public static func run(
        _ executable: String,
        _ arguments: [String],
        stdin: Data? = nil,
        inheritStderr: Bool = false,
        removingEnvironment: Set<String> = []
    ) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if !removingEnvironment.isEmpty {
            process.environment = ProcessInfo.processInfo.environment.filter { !removingEnvironment.contains($0.key) }
        }

        let output = Pipe()
        let errors = Pipe()
        let input = stdin.map { _ in Pipe() }
        process.standardOutput = output
        if !inheritStderr { process.standardError = errors }
        if let input { process.standardInput = input }

        do {
            try process.run()
        } catch {
            throw CommandError.launchFailed(executable, "\(error)")
        }

        // Drain both pipes concurrently so a chatty child cannot block on a full pipe.
        var stdoutData = Data()
        var stderrData = Data()
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) {
            stdoutData = output.fileHandleForReading.readDataToEndOfFile()
        }
        if !inheritStderr {
            DispatchQueue.global().async(group: group) {
                stderrData = errors.fileHandleForReading.readDataToEndOfFile()
            }
        }
        if let input, let stdin {
            input.fileHandleForWriting.write(stdin)
            try? input.fileHandleForWriting.close()
        }
        process.waitUntilExit()
        group.wait()
        return CommandResult(status: process.terminationStatus, stdout: stdoutData, stderr: stderrData)
    }
}

extension Command {
    /// Runs a tool in a new session with no controlling terminal.
    ///
    /// ssh-keygen reads passphrases from /dev/tty whenever a terminal exists,
    /// ignoring stdin. Without a controlling terminal it falls back to stdin,
    /// which is how the passphrase is handed over without echoing it or putting
    /// it on a command line.
    public static func runWithoutTerminal(
        _ executable: String,
        _ arguments: [String],
        stdin: Data,
        removingEnvironment: Set<String> = []
    ) throws -> CommandResult {
        var inputPipe: [Int32] = [0, 0], outputPipe: [Int32] = [0, 0], errorPipe: [Int32] = [0, 0]
        guard pipe(&inputPipe) == 0, pipe(&outputPipe) == 0, pipe(&errorPipe) == 0 else {
            throw CommandError.launchFailed(executable, "pipe: \(String(cString: strerror(errno)))")
        }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO)
        posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&actions, errorPipe[1], STDERR_FILENO)
        for fd in inputPipe + outputPipe + errorPipe {
            posix_spawn_file_actions_addclose(&actions, fd)
        }

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT))

        let environment = ProcessInfo.processInfo.environment
            .filter { !removingEnvironment.contains($0.key) }
            .map { "\($0.key)=\($0.value)" }
        var argv = ([executable] + arguments).map { strdup($0) } + [nil]
        var envp = environment.map { strdup($0) } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }

        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, executable, &actions, &attributes, &argv, &envp)
        close(inputPipe[0])
        close(outputPipe[1])
        close(errorPipe[1])
        guard spawned == 0 else {
            close(inputPipe[1]); close(outputPipe[0]); close(errorPipe[0])
            throw CommandError.launchFailed(executable, String(cString: strerror(spawned)))
        }

        let stdoutReader = FileHandle(fileDescriptor: outputPipe[0], closeOnDealloc: true)
        let stderrReader = FileHandle(fileDescriptor: errorPipe[0], closeOnDealloc: true)
        var stdoutData = Data()
        var stderrData = Data()
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) { stdoutData = stdoutReader.readDataToEndOfFile() }
        DispatchQueue.global().async(group: group) { stderrData = stderrReader.readDataToEndOfFile() }

        let writer = FileHandle(fileDescriptor: inputPipe[1], closeOnDealloc: true)
        signal(SIGPIPE, SIG_IGN)
        try? writer.write(contentsOf: stdin)
        try? writer.close()

        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0, errno == EINTR {}
        group.wait()
        let exitCode = (status & 0x7f) == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
        return CommandResult(status: exitCode, stdout: stdoutData, stderr: stderrData)
    }
}

/// File helpers shared by the identity, kit and inventory code.
public enum SecureFile {
    /// Overwrites a file with zeros, then removes it. Best effort only: APFS
    /// copy-on-write may keep old blocks around; FileVault protects those.
    public static func erase(_ url: URL) {
        if let handle = FileHandle(forWritingAtPath: url.path) {
            let size = (try? handle.seekToEnd()) ?? 0
            try? handle.seek(toOffset: 0)
            handle.write(Data(count: Int(size)))
            try? handle.synchronize()
            try? handle.close()
        }
        try? FileManager.default.removeItem(at: url)
    }

    /// Erases every regular file under `directory`, then removes it.
    public static func eraseDirectory(_ directory: URL) {
        if let files = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil) {
            for case let file as URL in files where !file.hasDirectoryPath {
                erase(file)
            }
        }
        try? FileManager.default.removeItem(at: directory)
    }

    /// Writes `contents` through a temporary file and renames it into place, so
    /// readers never see a partial file.
    public static func writeAtomically(_ contents: Data, to url: URL, mode: mode_t) throws {
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: temporary.path])
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: contents)
            try handle.synchronize()
            fchmod(fd, mode)
            try handle.close()
            guard rename(temporary.path, url.path) == 0 else {
                throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
            }
        } catch {
            unlink(temporary.path)
            throw error
        }
    }
}

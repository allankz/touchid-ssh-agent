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

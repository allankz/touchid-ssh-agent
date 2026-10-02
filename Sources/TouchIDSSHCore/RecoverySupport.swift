import Darwin
import Foundation

/// A throwaway ssh-agent that holds the emergency key for the length of a
/// recovery. The key is loaded with `ssh-add -` (the kit arrives on stdin, so
/// its file permissions do not matter) and the agent is killed afterwards.
public final class EmergencyAgent {
    public let directory: URL
    public var socket: URL { directory.appendingPathComponent("agent.sock") }
    /// Public half of the loaded key, for `IdentityFile` + `IdentitiesOnly`.
    public var publicKeyFile: URL { directory.appendingPathComponent("emergency.pub") }
    private let process = Process()
    private var stopped = false

    public init() throws {
        // Short path: Unix socket paths are limited to 104 bytes.
        var template = Array((NSTemporaryDirectory() + "tidrec-XXXXXX").utf8CString)
        guard let created = mkdtemp(&template) else { throw CocoaError(.fileWriteUnknown) }
        directory = URL(fileURLWithPath: String(cString: created))
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-agent")
        process.arguments = ["-D", "-a", directory.appendingPathComponent("agent.sock").path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        for _ in 0..<50 where !FileManager.default.fileExists(atPath: socket.path) { usleep(100_000) }
        guard FileManager.default.fileExists(atPath: socket.path) else {
            stop()
            throw RecoveryError.kitVerificationFailed("could not start a temporary ssh-agent")
        }
    }

    deinit { stop() }

    /// Loads the kit's key. ssh-add asks for the passphrase on the terminal.
    @discardableResult
    public func load(kit: Data, lifetimeSeconds: Int = 1800) throws -> RecoveryKey {
        let added = try Command.runAttachedToTerminal(
            "/usr/bin/ssh-add", ["-t", String(lifetimeSeconds), "-"], stdin: kit,
            environment: ["SSH_AUTH_SOCK": socket.path],
            removingEnvironment: EmergencyKitBuilder.askpassVariables
        )
        guard added.succeeded else {
            throw RecoveryError.kitVerificationFailed("ssh-add could not load the emergency key (wrong passphrase?)")
        }
        let listed = try Command.run("/usr/bin/ssh-add", ["-L"], environment: ["SSH_AUTH_SOCK": socket.path])
        guard let line = listed.stdoutText.split(whereSeparator: \.isNewline).first,
              let key = try? RecoveryKey(line: String(line)) else {
            throw RecoveryError.kitVerificationFailed("the emergency key did not load")
        }
        try SecureFile.writeAtomically(Data((key.line + "\n").utf8), to: publicKeyFile, mode: 0o600)
        return key
    }

    public func stop() {
        guard !stopped else { return }
        stopped = true
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        SecureFile.eraseDirectory(directory)
    }
}

/// How a recovery login checks the server's host key.
public enum KnownHostsPolicy {
    /// Only the host keys recorded in the inventory are accepted.
    case pinned(URL)
    /// No recorded keys (older inventories): trust on first use, write to `file`
    /// or to the configured known_hosts when nil.
    case acceptNew(URL?)

    var arguments: [String] {
        switch self {
        case .pinned(let file):
            return ["-o", "UserKnownHostsFile=\(file.path)", "-o", "StrictHostKeyChecking=yes"]
        case .acceptNew(let file):
            return (file.map { ["-o", "UserKnownHostsFile=\($0.path)"] } ?? []) + ["-o", "StrictHostKeyChecking=accept-new"]
        }
    }

    /// Writes the inventory's host keys into a known_hosts file for `resolved`.
    public static func pinned(_ keys: [String], for resolved: ResolvedTarget, in directory: URL) throws -> KnownHostsPolicy {
        let file = directory.appendingPathComponent("known_hosts-\(UUID().uuidString)")
        let text = keys.map { "\(resolved.knownHostsName) \($0)" }.joined(separator: "\n") + "\n"
        try SecureFile.writeAtomically(Data(text.utf8), to: file, mode: 0o600)
        return .pinned(file)
    }
}

extension RemoteKeys {
    static let listBegin = "TOUCHID-SSH-AGENT-BEGIN"
    static let listEnd = "TOUCHID-SSH-AGENT-END"

    /// Appends a listing of authorized_keys between markers.
    public static let listing = """
    echo "\(listBegin)"
    cat "$HOME/.ssh/authorized_keys" 2>/dev/null || true
    echo "\(listEnd)"

    """

    /// Lines of authorized_keys printed by `listing`.
    public static func listedLines(_ output: String) -> [String] {
        guard let start = output.range(of: listBegin + "\n"),
              let end = output.range(of: listEnd, range: start.upperBound..<output.endIndex) else { return [] }
        return output[start.upperBound..<end.lowerBound].split(whereSeparator: \.isNewline).map(String.init)
    }

    /// The key blob of an authorized_keys line, skipping any options before it.
    public static func keyBlob(inAuthorizedKeysLine line: String) -> Data? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        let fields = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        for (index, field) in fields.enumerated() where index + 1 < fields.count {
            if let blob = Data(base64Encoded: fields[index + 1]), SSHKeyFormat.keyTypeName(ofBlob: blob) == field {
                return blob
            }
        }
        return nil
    }

    /// Removes every line containing one of `blobs`, keeping the file's
    /// inode and permissions, then lists what is left.
    public static func removeScript(_ blobs: [Data]) -> String {
        var script = """
        set -e
        f="$HOME/.ssh/authorized_keys"
        umask 077
        t="$f.touchid.$$"
        cp "$f" "$t"

        """
        for blob in blobs {
            script += "grep -vF '\(blob.base64EncodedString())' \"$t\" > \"$t.n\" || true; mv \"$t.n\" \"$t\"\n"
        }
        script += "cat \"$t\" > \"$f\"\nrm -f \"$t\"\n" + listing
        return script
    }

    /// Runs `script` (or a bare login) as the emergency key held by `agent`.
    public static func emergencySession(
        _ target: SSHTarget, agent: EmergencyAgent, knownHosts: KnownHostsPolicy, script: String?
    ) -> (ok: Bool, output: String, error: String) {
        let arguments = target.baseArguments + [
            "-o", "IdentityAgent=\(agent.socket.path)",
            "-o", "IdentityFile=\(agent.publicKeyFile.path)",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
        ] + knownHosts.arguments + [target.destination, script == nil ? "exit 0" : "sh -s"]
        do {
            let result = try Command.run(ssh, arguments, stdin: Data((script ?? "").utf8))
            let error = result.stderrText.split(whereSeparator: \.isNewline).last.map(String.init) ?? "ssh exited with status \(result.status)"
            return (result.succeeded, result.stdoutText, result.succeeded ? "" : error)
        } catch {
            return (false, "", "\(error)")
        }
    }
}

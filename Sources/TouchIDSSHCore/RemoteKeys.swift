import Foundation

public enum RemoteKeysError: Error, CustomStringConvertible {
    case resolveFailed(String)
    case installFailed(String)

    public var description: String {
        switch self {
        case .resolveFailed(let detail): return "ssh could not resolve the destination: \(detail)"
        case .installFailed(let detail): return "Could not update authorized_keys on the server: \(detail)"
        }
    }
}

/// Where to connect, expressed the way ssh takes it.
public struct SSHTarget: Equatable {
    /// `host`, `user@host` or an alias from ssh_config.
    public var destination: String
    public var port: Int?
    /// `ssh -F` file; nil uses the user's normal configuration.
    public var configFile: String?
    /// Extra ssh arguments for the first connection of `authorize` only, for
    /// example `["-i", "~/.ssh/old_key"]` while the Touch ID key is not yet installed.
    public var bootstrapArguments: [String]

    public init(destination: String, port: Int? = nil, configFile: String? = nil, bootstrapArguments: [String] = []) {
        self.destination = destination
        self.port = port
        self.configFile = configFile
        self.bootstrapArguments = bootstrapArguments
    }

    /// Seconds ssh waits for the server to answer before giving up, so an
    /// unreachable host or a wrong port fails fast instead of hanging.
    public static let connectTimeout = 15

    var baseArguments: [String] {
        (configFile.map { ["-F", $0] } ?? []) + (port.map { ["-p", String($0)] } ?? [])
            + ["-o", "ConnectTimeout=\(SSHTarget.connectTimeout)"]
    }
}

public struct ResolvedTarget: Equatable {
    public let hostname: String
    public let user: String
    public let port: Int

    public init(hostname: String, user: String, port: Int) {
        self.hostname = hostname
        self.user = user
        self.port = port
    }
}

/// A public key to place in a server's `authorized_keys`.
public struct AuthorizedKey: Equatable {
    public let label: String
    public let type: String
    public let blob: Data
    public let comment: String

    public init(label: String, type: String, blob: Data, comment: String) {
        self.label = label
        self.type = type
        self.blob = blob
        self.comment = RemoteKeys.safeComment(comment)
    }

    public var base64: String { blob.base64EncodedString() }
    public var line: String { "\(type) \(base64) \(comment)" }
    public var fingerprint: String { SSHKeyFormat.fingerprint(blob: blob) }

    public static func login(_ identity: StoredIdentity) -> AuthorizedKey {
        AuthorizedKey(label: "login", type: SSHKeyFormat.keyType, blob: identity.publicKeyBlob, comment: identity.comment)
    }

    public static func recovery(_ key: RecoveryKey) -> AuthorizedKey {
        AuthorizedKey(label: "recovery", type: key.type, blob: key.blob, comment: key.comment)
    }
}

public enum LoginCheck: Equatable {
    /// ssh logged in and the server accepted the Touch ID key.
    case ok
    case agentNotRunning
    /// ssh logged in, but with some other key from the ssh configuration.
    case otherKeyUsed
    case failed(String)
}

public struct AuditOutcome: Equatable {
    public let login: LoginCheck
    /// Label → whether the key is in the server's authorized_keys.
    public let present: [String: Bool]

    public init(login: LoginCheck, present: [String: Bool]) {
        self.login = login
        self.present = present
    }
}

/// Installs and checks keys on servers by running small POSIX sh scripts over ssh.
public enum RemoteKeys {
    static let ssh = "/usr/bin/ssh"
    static let marker = "TOUCHID-SSH-AGENT"

    /// Key comments end up inside single-quoted shell strings on the server,
    /// so only a conservative character set is kept.
    public static func safeComment(_ comment: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._+:=,-")
        let mapped = String(comment.map { allowed.contains($0) ? $0 : "-" })
        let trimmed = String(mapped.prefix(80))
        return trimmed.isEmpty ? "key" : trimmed
    }

    /// Effective hostname, user and port, as `ssh -G` computes them.
    public static func resolve(_ target: SSHTarget) throws -> ResolvedTarget {
        let result = try Command.run(ssh, target.baseArguments + ["-G", target.destination])
        guard result.succeeded else {
            throw RemoteKeysError.resolveFailed(result.stderrText.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        var values: [String: String] = [:]
        for line in result.stdoutText.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: " ", maxSplits: 1)
            if parts.count == 2, values[String(parts[0])] == nil {
                values[String(parts[0])] = String(parts[1])
            }
        }
        guard let hostname = values["hostname"], let user = values["user"],
              let port = values["port"].flatMap(Int.init) else {
            throw RemoteKeysError.resolveFailed("unexpected ssh -G output")
        }
        return ResolvedTarget(hostname: hostname, user: user, port: port)
    }

    /// Appends each key unless its base64 blob is already present. Fixes a
    /// missing final newline first, so the new line never joins the last one.
    public static func installScript(_ keys: [AuthorizedKey]) -> String {
        var script = """
        set -e
        umask 077
        d="$HOME/.ssh"
        f="$d/authorized_keys"
        mkdir -p "$d"
        chmod 700 "$d"
        touch "$f"
        chmod 600 "$f"
        if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi

        """
        for key in keys {
            precondition(!key.line.contains("'"), "key lines are built from a safe character set")
            script += """
            if grep -qF '\(key.base64)' "$f"; then echo "\(marker) present \(key.label)"; \
            else printf '%s\\n' '\(key.line)' >> "$f"; echo "\(marker) added \(key.label)"; fi

            """
        }
        script += """
        if command -v restorecon >/dev/null 2>&1; then restorecon -F "$d" "$f" >/dev/null 2>&1 || true; fi

        """
        return script
    }

    static func checkScript(_ keys: [AuthorizedKey]) -> String {
        var script = "f=\"$HOME/.ssh/authorized_keys\"\n"
        for key in keys {
            script += """
            if [ -f "$f" ] && grep -qF '\(key.base64)' "$f"; then echo "\(marker) present \(key.label)"; \
            else echo "\(marker) missing \(key.label)"; fi

            """
        }
        return script
    }

    /// First connection of `authorize`: uses whatever access already works
    /// (password, another key, ssh_config). ssh's prompts go to the terminal.
    /// Returns label → true if the key was added, false if it was already there.
    public static func install(_ keys: [AuthorizedKey], on target: SSHTarget) throws -> [String: Bool] {
        let result = try Command.runAttachedToTerminal(
            ssh,
            target.baseArguments + target.bootstrapArguments + [target.destination, "sh -s"],
            stdin: Data(installScript(keys).utf8)
        )
        let report = parse(result.stdoutText)
        guard result.succeeded, keys.allSatisfy({ report[$0.label] != nil }) else {
            throw RemoteKeysError.installFailed("ssh exited with status \(result.status)")
        }
        return report.mapValues { $0 == "added" }
    }

    /// Logs in with the Touch ID key only and confirms from ssh's debug output
    /// that the server accepted that key. Costs one Touch ID approval.
    public static func verifyLogin(on target: SSHTarget, paths: AgentPaths, identity: StoredIdentity) -> LoginCheck {
        touchIDSession(target, paths: paths, identity: identity, script: nil).login
    }

    /// Logs in with the Touch ID key and reports which keys are installed.
    public static func audit(_ target: SSHTarget, keys: [AuthorizedKey], paths: AgentPaths, identity: StoredIdentity) -> AuditOutcome {
        let session = touchIDSession(target, paths: paths, identity: identity, script: checkScript(keys))
        return AuditOutcome(login: session.login, present: session.report.mapValues { $0 == "present" })
    }

    static func touchIDSession(
        _ target: SSHTarget, paths: AgentPaths, identity: StoredIdentity, script: String?
    ) -> (login: LoginCheck, report: [String: String]) {
        guard AgentClient.isListening(socketPath: paths.socket.path) else { return (.agentNotRunning, [:]) }
        let arguments = target.baseArguments + [
            "-v",
            "-o", "IdentityAgent=\(paths.socket.path)",
            "-o", "IdentityFile=\(paths.publicKeyFile.path)",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            // A shared connection would "log in" without authenticating at all.
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            target.destination, script == nil ? "exit 0" : "sh -s",
        ]
        let result: CommandResult
        do {
            result = try Command.run(ssh, arguments, stdin: Data((script ?? "").utf8))
        } catch {
            return (.failed("\(error)"), [:])
        }
        guard result.succeeded else {
            let lastError = result.stderrText.split(whereSeparator: \.isNewline)
                .last { !$0.hasPrefix("debug") }.map(String.init) ?? "ssh exited with status \(result.status)"
            return (.failed(lastError), [:])
        }
        let accepted = result.stderrText.split(whereSeparator: \.isNewline).contains {
            $0.contains("Server accepts key:") && $0.contains(identity.fingerprint)
        }
        return (accepted ? .ok : .otherKeyUsed, parse(result.stdoutText))
    }

    /// Reads the "TOUCHID-SSH-AGENT <status> <label>" lines a script printed,
    /// ignoring anything else the remote shell may print.
    public static func parse(_ output: String) -> [String: String] {
        var report: [String: String] = [:]
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: " ")
            if parts.count == 3, parts[0] == Substring(marker) {
                report[String(parts[2])] = String(parts[1])
            }
        }
        return report
    }
}

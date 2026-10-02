import Foundation

/// The user's ssh_config file: render, append and amend `Host` blocks that
/// route a server through the Touch ID agent.
public struct SSHConfigFile {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    /// `~/.ssh/config`, or the `-F` file the user passed.
    public static func forTarget(configFile: String?) -> SSHConfigFile {
        SSHConfigFile(url: URL(fileURLWithPath: (configFile ?? "~/.ssh/config" as String).expandingTildeInPathString))
    }

    /// The agent lines every Touch ID host block carries.
    public static func agentLines(paths: AgentPaths) -> [String] {
        [
            "IdentityAgent \(paths.displayPath(paths.socket))",
            "IdentityFile \(paths.displayPath(paths.publicKeyFile))",
            "IdentitiesOnly yes",
            "ForwardAgent no",
        ]
    }

    public static func block(alias: String, hostname: String, user: String?, port: Int?, paths: AgentPaths) -> String {
        var lines = ["Host \(alias)", "  HostName \(hostname)"]
        if let user { lines.append("  User \(user)") }
        if let port { lines.append("  Port \(port)") }
        lines += agentLines(paths: paths).map { "  " + $0 }
        return lines.joined(separator: "\n")
    }

    /// Names declared on `Host` lines, without wildcard or negated patterns.
    public func hostAliases() -> [String] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var aliases: [String] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let keyword = fields.first, keyword.lowercased() == "host" else { continue }
            for pattern in fields.dropFirst() where !pattern.contains("*") && !pattern.contains("?") && !pattern.hasPrefix("!") {
                aliases.append(String(pattern))
            }
        }
        return aliases
    }

    /// Appends a block at the end of the file, creating it (0600) if needed.
    public func append(block: String) throws {
        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        var text = existing
        if !text.isEmpty, !text.hasSuffix("\n") { text += "\n" }
        if !text.isEmpty { text += "\n" }
        text += "# Added by touchid-ssh-agent\n" + block + "\n"
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try SecureFile.writeAtomically(Data(text.utf8), to: url, mode: existingMode() ?? 0o600)
    }

    /// Inserts the agent lines right after `Host alias`, after saving a copy of
    /// the file next to it. Returns the backup's URL.
    @discardableResult
    public func insertAgentLines(intoHost alias: String, paths: AgentPaths) throws -> URL {
        let text = try String(contentsOf: url, encoding: .utf8)
        var lines = text.components(separatedBy: "\n")
        guard let index = lines.firstIndex(where: { line in
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            return fields.first?.lowercased() == "host" && fields.dropFirst().contains(Substring(alias))
        }) else {
            throw CocoaError(.fileReadUnknown, userInfo: [NSLocalizedDescriptionKey: "Host \(alias) not found in \(url.path)"])
        }
        let backup = url.appendingPathExtension("touchid-backup")
        try? FileManager.default.removeItem(at: backup)
        try FileManager.default.copyItem(at: url, to: backup)
        lines.insert(contentsOf: Self.agentLines(paths: paths).map { "  " + $0 }, at: index + 1)
        try SecureFile.writeAtomically(Data(lines.joined(separator: "\n").utf8), to: url, mode: existingMode() ?? 0o600)
        return backup
    }

    private func existingMode() -> mode_t? {
        ((try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int).map { mode_t($0) }
    }
}

extension String {
    var expandingTildeInPathString: String { (self as NSString).expandingTildeInPath }
}

/// Host keys for a server as recorded in the user's known_hosts files.
public enum HostKeys {
    /// `type base64` entries ssh already trusts for `resolved`.
    public static func known(for resolved: ResolvedTarget) -> [String] {
        var keys: [String] = []
        for file in resolved.userKnownHostsFiles {
            let path = file.expandingTildeInPathString
            guard FileManager.default.fileExists(atPath: path),
                  let result = try? Command.run("/usr/bin/ssh-keygen", ["-F", resolved.knownHostsName, "-f", path]) else { continue }
            for line in result.stdoutText.split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
                let fields = line.split(separator: " ")
                if fields.count >= 3 { keys.append("\(fields[1]) \(fields[2])") }
            }
        }
        var seen = Set<String>()
        return keys.filter { seen.insert($0).inserted }
    }

    /// Adds `keys` for `resolved` to its first known_hosts file, skipping any
    /// already present, so later logins on this Mac trust the server.
    public static func remember(_ keys: [String], for resolved: ResolvedTarget) throws {
        let present = Set(known(for: resolved))
        let missing = keys.filter { !present.contains($0) }
        guard !missing.isEmpty, let first = resolved.userKnownHostsFiles.first else { return }
        let url = URL(fileURLWithPath: first.expandingTildeInPathString)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        var text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        if !text.isEmpty, !text.hasSuffix("\n") { text += "\n" }
        text += missing.map { "\(resolved.knownHostsName) \($0)" }.joined(separator: "\n") + "\n"
        let mode = ((try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int).map { mode_t($0) }
        try SecureFile.writeAtomically(Data(text.utf8), to: url, mode: mode ?? 0o644)
    }
}

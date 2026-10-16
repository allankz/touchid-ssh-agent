import CryptoKit
import Darwin
import Foundation

public enum AccessError: Error, CustomStringConvertible {
    case invalid(code: String, message: String)

    public var code: String {
        switch self { case .invalid(let code, _): return code }
    }

    public var description: String {
        switch self { case .invalid(_, let message): return message }
    }
}

/// What a grant lets the selected accounts do, the same for every target.
public struct AccessPermissions: Codable, Equatable {
    /// When set, the server runs only this command (certificate `force-command`).
    public var forceCommand: String?
    /// `permit-pty`. Forwarding and user rc are never permitted in this version.
    public var pty: Bool

    public init(forceCommand: String? = nil, pty: Bool = false) {
        self.forceCommand = forceCommand
        self.pty = pty
    }

    public var criticalOptions: [CertificateOption] {
        forceCommand.map { [CertificateOption.forceCommand($0)] } ?? []
    }

    public var extensions: [CertificateOption] {
        pty ? [CertificateOption.flag("permit-pty")] : []
    }
}

/// One validated destination of a grant, frozen before approval.
public struct AccessTarget: Codable, Equatable {
    /// The item as the user or AI typed it.
    public var requested: String
    public var inventoryAlias: String
    public var targetId: String
    public var principal: String
    public var hostname: String
    public var user: String
    public var port: Int
    /// Host keys recorded in the inventory; the grant's ssh_config pins them.
    public var hostKeys: [String]
    /// The dated alias defined in the grant's own ssh_config.
    public var sshAlias: String
    /// Transport settings carried over from the user's ssh configuration
    /// (keyword → value), never anything that selects credentials.
    public var transport: [String: String]

    public init(requested: String, inventoryAlias: String, targetId: String, principal: String, hostname: String,
                user: String, port: Int, hostKeys: [String], sshAlias: String, transport: [String: String] = [:]) {
        self.requested = requested
        self.inventoryAlias = inventoryAlias
        self.targetId = targetId
        self.principal = principal
        self.hostname = hostname
        self.user = user
        self.port = port
        self.hostKeys = hostKeys
        self.sshAlias = sshAlias
        self.transport = transport
    }
}

/// The complete, immutable request a grant job signs. The CLI writes it before
/// showing the summary and passes its SHA-256 to the job, which refuses any
/// other bytes, so what was shown is exactly what gets signed.
public struct AccessRequest: Codable, Equatable {
    public var schemaVersion = 1
    public var grantId: String
    public var dataDirectory: String
    public var caFingerprint: String
    public var targets: [AccessTarget]
    public var permissions: AccessPermissions
    public var requestedAt: UInt64
    public var validAfter: UInt64
    public var validBefore: UInt64

    public init(grantId: String, dataDirectory: String, caFingerprint: String, targets: [AccessTarget],
                permissions: AccessPermissions, requestedAt: UInt64, duration: UInt64) {
        self.grantId = grantId
        self.dataDirectory = dataDirectory
        self.caFingerprint = caFingerprint
        self.targets = targets
        self.permissions = permissions
        self.requestedAt = requestedAt
        validAfter = requestedAt - CertificateIssuer.clockSkewMargin
        validBefore = requestedAt + duration
    }

    public var expiresAt: Date { Date(timeIntervalSince1970: TimeInterval(validBefore)) }
    public var duration: UInt64 { validBefore - requestedAt }
    public var principals: [String] { targets.map(\.principal) }

    public func encoded() throws -> Data { try JSON.encode(self) }

    public static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Structural checks, repeated by the job before it signs anything.
    public func validate() throws {
        guard schemaVersion == 1, AccessNames.isGrantId(grantId) else {
            throw AccessError.invalid(code: "invalid_request", message: "malformed grant request")
        }
        guard !targets.isEmpty else {
            throw AccessError.invalid(code: "invalid_request", message: "the request has no target")
        }
        guard validBefore > requestedAt, duration <= AccessDuration.maximum,
              validAfter == requestedAt - CertificateIssuer.clockSkewMargin else {
            throw AccessError.invalid(code: "invalid_duration", message: "the grant duration must be between 1 second and 12 hours")
        }
        guard Set(targets.map(\.targetId)).count == targets.count,
              Set(targets.map(\.sshAlias)).count == targets.count,
              Set(principals).count == targets.count,
              principals.allSatisfy(SSHCertificate.isValidPrincipal) else {
            throw AccessError.invalid(code: "invalid_request", message: "duplicate or invalid targets in the request")
        }
        if let command = permissions.forceCommand {
            try AccessPermissions.validateForceCommand(command)
        }
        for target in targets {
            guard !target.hostKeys.isEmpty else {
                throw AccessError.invalid(code: "host_key_missing", message: "no recorded host key for \(target.inventoryAlias)")
            }
            _ = try GrantSSHConfig.hostName(target.hostname)
            _ = try GrantSSHConfig.userName(target.user)
            guard AccessNames.isAlias(target.sshAlias), (1...65535).contains(target.port) else {
                throw AccessError.invalid(code: "invalid_request", message: "invalid alias or port in the request")
            }
        }
    }
}

extension AccessPermissions {
    public static func validateForceCommand(_ command: String) throws {
        guard !command.trimmingCharacters(in: .whitespaces).isEmpty, command.count <= 1024,
              !command.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw AccessError.invalid(code: "invalid_arguments",
                                      message: "--force-command needs a non-empty command of at most 1024 characters, on one line")
        }
    }
}

/// Durations such as `30m`, `2h`, `1h30m` or `45s`, at most 12 hours.
public enum AccessDuration {
    public static let maximum: UInt64 = 12 * 3600

    public static func parse(_ text: String) throws -> UInt64 {
        let invalid = AccessError.invalid(
            code: "invalid_duration",
            message: "--for needs a positive duration such as 30m, 2h or 1h30m (at most 12h); got \"\(DisplayText.sanitize(text, maxLength: 40))\"")
        guard text.range(of: "^([0-9]+h)?([0-9]+m)?([0-9]+s)?$", options: .regularExpression) != nil, !text.isEmpty else {
            throw invalid
        }
        var total: UInt64 = 0
        var digits = ""
        for character in text {
            if character.isNumber {
                digits.append(character)
                guard digits.count <= 6 else { throw invalid }
                continue
            }
            guard let value = UInt64(digits) else { throw invalid }
            switch character {
            case "h": total += value * 3600
            case "m": total += value * 60
            default: total += value
            }
            digits = ""
        }
        guard total > 0 else { throw invalid }
        guard total <= maximum else {
            throw AccessError.invalid(code: "invalid_duration", message: "--for is at most 12h; request a shorter grant")
        }
        return total
    }

    /// "2 hours", "1 hour 30 minutes", "45 seconds".
    public static func describe(_ seconds: UInt64) -> String {
        func unit(_ value: UInt64, _ name: String) -> String? {
            value == 0 ? nil : "\(value) \(name)\(value == 1 ? "" : "s")"
        }
        let parts = [unit(seconds / 3600, "hour"), unit(seconds % 3600 / 60, "minute"), unit(seconds % 60, "second")]
            .compactMap { $0 }
        return parts.isEmpty ? "0 seconds" : parts.joined(separator: " ")
    }
}

/// Grant identifiers and dated aliases.
public enum AccessNames {
    /// `YYYYMMDD-` (local date) followed by 12 random hex digits.
    public static func newGrantId(date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd"
        var generator = SystemRandomNumberGenerator()
        let random = (0..<6).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &generator)) }.joined()
        return "\(formatter.string(from: date))-\(random)"
    }

    public static func isGrantId(_ text: String) -> Bool {
        text.range(of: "^[0-9]{8}-[0-9a-f]{12}$", options: .regularExpression) != nil
    }

    public static func isAlias(_ text: String) -> Bool {
        text.count <= 80 && text.range(of: "^[a-z0-9][a-z0-9._-]*-access-[0-9]{8}-[0-9a-f]{12}$", options: .regularExpression) != nil
    }

    /// A literal ssh_config host name made from an inventory alias: lowercase
    /// letters, digits, dots, dashes and underscores, at most 32 characters.
    public static func label(_ alias: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789._-")
        var label = String(alias.lowercased().map { allowed.contains($0) ? $0 : "-" })
        while label.contains("--") { label = label.replacingOccurrences(of: "--", with: "-") }
        label = String(label.trimmingCharacters(in: CharacterSet(charactersIn: "-._")).prefix(32))
        label = label.trimmingCharacters(in: CharacterSet(charactersIn: "-._"))
        return label.isEmpty ? "target" : label
    }

    /// `<label>-access-<grant-id>` for each alias, made unique within the grant.
    public static func aliases(for inventoryAliases: [String], grantId: String) -> [String] {
        var used = Set<String>()
        return inventoryAliases.map { alias in
            let base = label(alias)
            var candidate = "\(base)-access-\(grantId)"
            var counter = 2
            while used.contains(candidate) {
                candidate = "\(base)-\(counter)-access-\(grantId)"
                counter += 1
            }
            used.insert(candidate)
            return candidate
        }
    }
}

/// Where a grant's (or a validation check's) published files live.
public struct GrantFiles {
    public let agentSocket: URL
    public let publicKey: URL
    public let certificate: URL
    public let sshConfig: URL
    public let knownHosts: URL

    public init(directory: URL) {
        agentSocket = directory.appendingPathComponent(GrantDirectory.agentSocketName)
        publicKey = directory.appendingPathComponent(GrantDirectory.publicKeyName)
        certificate = directory.appendingPathComponent(GrantDirectory.certificateName)
        sshConfig = directory.appendingPathComponent(GrantDirectory.sshConfigName)
        knownHosts = directory.appendingPathComponent(GrantDirectory.knownHostsName)
    }
}

/// Files of one grant directory, `access/grants/<grant-id>/`.
public struct GrantDirectory {
    public static let manifestName = "manifest.json"
    public static let requestName = "request.json"
    public static let plistName = "job.plist"
    public static let controlSocketName = "control.sock"
    public static let agentSocketName = "agent.sock"
    public static let publicKeyName = "key.pub"
    public static let certificateName = "key-cert.pub"
    public static let sshConfigName = "ssh_config"
    public static let knownHostsName = "known_hosts"
    /// Everything this feature may create inside a grant directory.
    public static let ownedNames: [String] = [
        manifestName, requestName, plistName, controlSocketName, agentSocketName,
        publicKeyName, certificateName, sshConfigName, knownHostsName,
    ]
    static let socketNames: Set<String> = [controlSocketName, agentSocketName]

    public let url: URL
    public var grantId: String { url.lastPathComponent }

    public init(paths: AgentPaths, grantId: String) {
        url = paths.grantsDirectory.appendingPathComponent(grantId)
    }

    public var manifest: URL { url.appendingPathComponent(Self.manifestName) }
    public var request: URL { url.appendingPathComponent(Self.requestName) }
    public var plist: URL { url.appendingPathComponent(Self.plistName) }
    public var controlSocket: URL { url.appendingPathComponent(Self.controlSocketName) }
    public var agentSocket: URL { url.appendingPathComponent(Self.agentSocketName) }
    public var publicKey: URL { url.appendingPathComponent(Self.publicKeyName) }
    public var certificate: URL { url.appendingPathComponent(Self.certificateName) }
    public var sshConfig: URL { url.appendingPathComponent(Self.sshConfigName) }
    public var knownHosts: URL { url.appendingPathComponent(Self.knownHostsName) }
    public var files: GrantFiles { GrantFiles(directory: url) }

    /// Fails before approval when a grant socket path would not fit in a
    /// `sockaddr_un` (for example with a long custom data directory).
    public static func checkSocketPathLength(paths: AgentPaths) throws {
        let sample = GrantDirectory(paths: paths, grantId: "00000000-000000000000")
        let longest = max(sample.controlSocket.path.utf8.count, sample.agentSocket.path.utf8.count)
        guard longest <= UnixSocket.maxPathLength else {
            throw AccessError.invalid(code: "socket_path_too_long", message: """
            the grant socket path would be \(longest) bytes, more than the \(UnixSocket.maxPathLength) a Unix socket \
            allows. Use a shorter data directory (\(AgentPaths.environmentVariable)).
            """)
        }
    }

    /// Creates the directory (0700). Fails if it exists, so a grant never reuses
    /// another grant's path.
    public func create() throws {
        guard mkdir(url.path, 0o700) == 0 else {
            throw AccessError.invalid(code: "internal_error", message: "cannot create \(url.path): \(String(cString: strerror(errno)))")
        }
    }
}

/// Identifies a running process by pid and start time, so a reused pid is
/// never mistaken for the grant's job.
public struct ProcessIdentity: Codable, Equatable {
    public var pid: Int32
    public var startSeconds: UInt64
    public var startMicroseconds: UInt64

    public init(pid: Int32, startSeconds: UInt64, startMicroseconds: UInt64) {
        self.pid = pid
        self.startSeconds = startSeconds
        self.startMicroseconds = startMicroseconds
    }

    public static func of(pid: pid_t) -> ProcessIdentity? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard pid > 0, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size, info.pbi_uid == getuid() else { return nil }
        // A zombie has exited; it only waits for its parent.
        guard info.pbi_status != UInt32(SZOMB) else { return nil }
        return ProcessIdentity(pid: pid, startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec)
    }

    public static func current() -> ProcessIdentity? { of(pid: getpid()) }

    public var isRunning: Bool { ProcessIdentity.of(pid: pid) == self }
}

/// Ownership record of a grant directory. Cleanup removes a directory only
/// when its manifest names it and this data directory.
public struct GrantManifest: Codable, Equatable {
    public static let kind = "touchid-ssh-agent-access-grant"

    public struct Target: Codable, Equatable {
        public var targetId: String
        public var sshAlias: String
    }

    public var schemaVersion = 1
    public var kind = GrantManifest.kind
    public var grantId: String
    public var dataDirectory: String
    /// launchd label of the job, when it runs under launchd.
    public var launchLabel: String?
    public var createdAt: UInt64
    public var expiresAt: UInt64
    public var targets: [Target]
    public var files: [String] = GrantDirectory.ownedNames
    /// The job process, recorded by the job itself as its first step.
    public var process: ProcessIdentity?

    public init(request: AccessRequest, launchLabel: String?) {
        grantId = request.grantId
        dataDirectory = request.dataDirectory
        self.launchLabel = launchLabel
        createdAt = request.requestedAt
        expiresAt = request.validBefore
        targets = request.targets.map { Target(targetId: $0.targetId, sshAlias: $0.sshAlias) }
    }

    public func write(to directory: GrantDirectory) throws {
        try SecureFile.writeAtomically(try JSON.encode(self), to: directory.manifest, mode: 0o600)
    }

    public static func read(from directory: GrantDirectory) -> GrantManifest? {
        GrantStore.readSmallFile(directory.manifest).flatMap { try? JSON.decoder.decode(GrantManifest.self, from: $0) }
    }
}

/// The ssh_config and known_hosts a grant publishes.
public enum GrantSSHConfig {
    /// Keywords copied from the user's configuration: transport only.
    public static let transportKeywords = ["addressfamily", "connecttimeout", "serveraliveinterval", "serveralivecountmax", "tcpkeepalive"]
    static let keywordNames = ["addressfamily": "AddressFamily", "connecttimeout": "ConnectTimeout",
                               "serveraliveinterval": "ServerAliveInterval", "serveralivecountmax": "ServerAliveCountMax",
                               "tcpkeepalive": "TCPKeepAlive"]

    /// A path for ssh_config: `%` escaped (ssh expands tokens in these
    /// keywords), quoted when it holds spaces. Quotes and control characters
    /// cannot be represented and are refused.
    public static func path(_ url: URL) throws -> String {
        let path = url.path
        guard !path.contains("\""), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw AccessError.invalid(code: "unsupported_configuration",
                                      message: "the data directory path contains a quote or control character, which ssh_config cannot express")
        }
        let escaped = path.replacingOccurrences(of: "%", with: "%%")
        return escaped.contains(" ") || escaped.contains("\t") ? "\"\(escaped)\"" : escaped
    }

    static func hostName(_ name: String) throws -> String {
        guard !name.isEmpty, name.count <= 253,
              name.range(of: "^[A-Za-z0-9._:%\\[\\]-]+$", options: .regularExpression) != nil else {
            throw AccessError.invalid(code: "unsupported_configuration", message: "unsupported host name \(DisplayText.sanitize(name, maxLength: 60))")
        }
        return name.replacingOccurrences(of: "%", with: "%%")
    }

    static func userName(_ name: String) throws -> String {
        guard !name.isEmpty, name.count <= 64,
              name.range(of: "^[A-Za-z0-9._@+-]+$", options: .regularExpression) != nil else {
            throw AccessError.invalid(code: "unsupported_configuration", message: "unsupported account name \(DisplayText.sanitize(name, maxLength: 40))")
        }
        return name
    }

    /// Host blocks for each alias that select only the grant's key and
    /// certificate, pin the recorded host keys and disable forwarding and
    /// connection sharing; then a catch-all block that makes any other name
    /// fail without a network connection or credentials.
    public static func render(_ request: AccessRequest, in directory: GrantDirectory) throws -> String {
        try render(request, files: directory.files)
    }

    public static func render(_ request: AccessRequest, files: GrantFiles) throws -> String {
        var lines = [
            "# touchid-ssh-agent temporary access grant \(request.grantId)",
            "# Expires \(ISO8601DateFormatter().string(from: request.expiresAt)). Removed when the grant ends; do not edit.",
            "# Use: ssh -F <this file> ALIAS [COMMAND]",
        ]
        let knownHosts = try path(files.knownHosts)
        let agent = try path(files.agentSocket)
        let key = try path(files.publicKey)
        let certificate = try path(files.certificate)
        for target in request.targets {
            lines += [
                "",
                "Host \(target.sshAlias)",
                "  HostName \(try hostName(target.hostname))",
                "  User \(try userName(target.user))",
                "  Port \(target.port)",
                "  HostKeyAlias \(target.sshAlias)",
                "  UserKnownHostsFile \(knownHosts)",
                "  GlobalKnownHostsFile /dev/null",
                "  StrictHostKeyChecking yes",
                "  UpdateHostKeys no",
                "  CheckHostIP no",
                "  IdentityAgent \(agent)",
                "  IdentityFile \(key)",
                "  CertificateFile \(certificate)",
                "  IdentitiesOnly yes",
                "  PreferredAuthentications publickey",
                "  PubkeyAuthentication yes",
                "  PasswordAuthentication no",
                "  KbdInteractiveAuthentication no",
                "  HostbasedAuthentication no",
                "  BatchMode yes",
                "  ForwardAgent no",
                "  ForwardX11 no",
                "  ClearAllForwardings yes",
                "  PermitLocalCommand no",
                "  ControlMaster no",
                "  ControlPath none",
                "  ControlPersist no",
                "  ProxyCommand none",
                "  ProxyJump none",
            ]
            if !request.permissions.pty { lines.append("  RequestTTY no") }
            var transport = target.transport
            if transport["connecttimeout"] == nil { transport["connecttimeout"] = String(SSHTarget.connectTimeout) }
            for keyword in transportKeywords {
                guard let value = transport[keyword], let name = keywordNames[keyword],
                      value.range(of: "^[A-Za-z0-9]+$", options: .regularExpression) != nil else { continue }
                lines.append("  \(name) \(value)")
            }
        }
        lines += [
            "",
            "# Any other name fails here: no DNS lookup, no personal keys, no other agent.",
            "Host * " + request.targets.map { "!\($0.sshAlias)" }.joined(separator: " "),
            "  ProxyCommand /usr/bin/false",
            "  IdentityAgent none",
            "  IdentitiesOnly yes",
            "  PubkeyAuthentication no",
            "  PasswordAuthentication no",
            "  KbdInteractiveAuthentication no",
            "  BatchMode yes",
            "",
        ]
        return lines.joined(separator: "\n")
    }

    /// known_hosts entries under each dated alias (its `HostKeyAlias`).
    public static func knownHosts(_ request: AccessRequest) -> String {
        request.targets.flatMap { target in target.hostKeys.map { "\(target.sshAlias) \($0)" } }
            .joined(separator: "\n") + "\n"
    }

    /// The exact argv to reach `target`; a remote command goes after it.
    public static func argv(_ target: AccessTarget, in directory: GrantDirectory) -> [String] {
        ["ssh", "-F", directory.sshConfig.path, target.sshAlias]
    }
}

/// What cleanup and status find in `access/grants/`.
public struct GrantInspection {
    public let grantId: String
    public let directory: URL
    public let manifest: GrantManifest?
    /// Why ownership or liveness is uncertain; such directories are never removed.
    public let problem: String?
    /// The recorded job process is still running (pid and start time match).
    public let running: Bool
    /// The directory holds nothing at all.
    public let empty: Bool

    public var expired: Bool {
        guard let manifest else { return false }
        return Date().timeIntervalSince1970 >= TimeInterval(manifest.expiresAt)
    }
}

public enum GrantStore {
    static let temporaryName = "^\\.(manifest\\.json|request\\.json|job\\.plist|ssh_config|known_hosts|key\\.pub|key-cert\\.pub)\\.[0-9A-F-]{36}\\.tmp$"

    /// Every entry of the grants directory, sorted by name.
    public static func inspectAll(paths: AgentPaths) -> [GrantInspection] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: paths.grantsDirectory.path)) ?? []
        return names.sorted().map { inspect(name: $0, paths: paths) }
    }

    public static func inspect(name: String, paths: AgentPaths) -> GrantInspection {
        let url = paths.grantsDirectory.appendingPathComponent(name)
        func uncertain(_ problem: String, manifest: GrantManifest? = nil, running: Bool = false) -> GrantInspection {
            GrantInspection(grantId: name, directory: url, manifest: manifest, problem: problem, running: running, empty: false)
        }
        guard AccessNames.isGrantId(name) else { return uncertain("unexpected entry, not created by this tool") }
        var info = stat()
        guard lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR else {
            return uncertain("not a real directory (symlink or file)")
        }
        guard info.st_uid == getuid() else { return uncertain("owned by another user") }
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: url.path) else {
            return uncertain("cannot list the directory")
        }
        if entries.isEmpty {
            return GrantInspection(grantId: name, directory: url, manifest: nil, problem: nil, running: false, empty: true)
        }
        for entry in entries {
            guard GrantDirectory.ownedNames.contains(entry) || entry.range(of: temporaryName, options: .regularExpression) != nil else {
                return uncertain("unexpected file \(DisplayText.sanitize(entry, maxLength: 40))")
            }
            var entryInfo = stat()
            guard lstat(url.appendingPathComponent(entry).path, &entryInfo) == 0, entryInfo.st_uid == getuid() else {
                return uncertain("cannot check \(entry)")
            }
            let type = entryInfo.st_mode & S_IFMT
            let expected = GrantDirectory.socketNames.contains(entry) ? S_IFSOCK : S_IFREG
            guard type == expected else { return uncertain("\(entry) is not a \(expected == S_IFSOCK ? "socket" : "regular file")") }
        }
        let manifestURL = url.appendingPathComponent(GrantDirectory.manifestName)
        guard let data = readSmallFile(manifestURL), let manifest = try? JSON.decoder.decode(GrantManifest.self, from: data) else {
            return uncertain("no valid manifest")
        }
        guard manifest.kind == GrantManifest.kind, manifest.grantId == name,
              manifest.dataDirectory == paths.directory.path else {
            return uncertain("the manifest does not describe this directory", manifest: manifest)
        }
        let running = manifest.process?.isRunning ?? false
        return GrantInspection(grantId: name, directory: url, manifest: manifest, problem: nil, running: running, empty: false)
    }

    /// Removes the owned files of an inspected, ownership-checked directory,
    /// then the directory. Works through directory descriptors opened without
    /// following symlinks, so nothing outside the grant directory is touched.
    public static func remove(_ inspection: GrantInspection, paths: AgentPaths) throws {
        guard inspection.problem == nil else {
            throw AccessError.invalid(code: "cleanup_refused", message: inspection.problem ?? "uncertain ownership")
        }
        if let failure = removeOwnedFiles(grantId: inspection.grantId, paths: paths) {
            throw AccessError.invalid(code: "cleanup_refused", message: failure)
        }
    }

    /// Unlinks only the names this feature creates, then the (then empty)
    /// directory. Returns why something was left, or nil.
    @discardableResult
    public static func removeOwnedFiles(grantId: String, paths: AgentPaths) -> String? {
        guard AccessNames.isGrantId(grantId) else { return "not a grant directory" }
        let parent = open(paths.grantsDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { return "cannot open the grants directory" }
        defer { close(parent) }
        let directory = openat(parent, grantId, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return errno == ENOENT ? nil : "cannot open \(grantId)" }
        defer { close(directory) }
        let url = paths.grantsDirectory.appendingPathComponent(grantId)
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        for entry in entries where GrantDirectory.ownedNames.contains(entry) || entry.range(of: temporaryName, options: .regularExpression) != nil {
            if unlinkat(directory, entry, 0) != 0, errno != ENOENT {
                return "cannot remove \(entry): \(String(cString: strerror(errno)))"
            }
        }
        if unlinkat(parent, grantId, AT_REMOVEDIR) != 0, errno != ENOENT {
            return "\(grantId) still holds files that this tool did not create"
        }
        return nil
    }

    /// Reads a regular file of at most 1 MiB without following symlinks.
    static func readSmallFile(_ url: URL, limit: Int = 1 << 20) -> Data? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size <= limit else { return nil }
        return try? handle.readToEnd() ?? Data()
    }

    public static func readRequest(_ directory: GrantDirectory) -> (data: Data, request: AccessRequest)? {
        guard let data = readSmallFile(directory.request),
              let request = try? JSON.decoder.decode(AccessRequest.self, from: data) else { return nil }
        return (data, request)
    }
}

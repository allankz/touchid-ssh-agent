import Foundation

/// User settings stored in `config.json`.
public struct AgentSettings: Codable, Equatable {
    /// Folder (normally synced to a cloud service) that receives the encrypted
    /// inventory backup. Nil when the user chose not to keep one.
    public var backupPath: String?

    public init(backupPath: String? = nil) {
        self.backupPath = backupPath
    }

    public var backupDirectory: URL? {
        backupPath.map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) }
    }
}

public enum SettingsStore {
    public static func load(from paths: AgentPaths) -> AgentSettings {
        guard let data = FileManager.default.contents(atPath: paths.settingsFile.path),
              let settings = try? JSONDecoder().decode(AgentSettings.self, from: data) else {
            return AgentSettings()
        }
        return settings
    }

    public static func save(_ settings: AgentSettings, to paths: AgentPaths) throws {
        try paths.ensureDirectory()
        try SecureFile.writeAtomically(try JSON.encode(settings), to: paths.settingsFile, mode: 0o600)
    }
}

/// One server where `authorize` installed the login and emergency keys.
public struct InventoryEntry: Codable, Equatable {
    /// Name used to refer to the server; defaults to the destination as typed.
    public var alias: String
    /// Destination passed to ssh (`host`, `user@host` or an ssh_config alias).
    public var destination: String
    public var hostname: String
    public var user: String
    public var port: Int
    /// `ssh -F` file used at authorization time, if any.
    public var sshConfigFile: String?
    public var loginKeyFingerprint: String
    public var recoveryKeyFingerprint: String
    public var authorizedAt: Date
    public var lastAudit: Date?
    public var lastAuditResult: String?
    /// Server host keys (`type base64`) as trusted when the entry was
    /// recorded, so a recovery from a new Mac can verify the server.
    public var hostKeys: [String]?

    public init(
        alias: String, destination: String, hostname: String, user: String, port: Int,
        sshConfigFile: String?, loginKeyFingerprint: String, recoveryKeyFingerprint: String,
        authorizedAt: Date, lastAudit: Date? = nil, lastAuditResult: String? = nil, hostKeys: [String]? = nil
    ) {
        self.alias = alias
        self.destination = destination
        self.hostname = hostname
        self.user = user
        self.port = port
        self.sshConfigFile = sshConfigFile
        self.loginKeyFingerprint = loginKeyFingerprint
        self.recoveryKeyFingerprint = recoveryKeyFingerprint
        self.authorizedAt = authorizedAt
        self.lastAudit = lastAudit
        self.lastAuditResult = lastAuditResult
        self.hostKeys = hostKeys
    }
}

/// The list of servers to recover access to. Kept locally in `inventory.json`
/// and, encrypted to the emergency key, in the backup folder.
public struct Inventory: Codable, Equatable {
    public var version = 1
    public var mac: String
    public var updatedAt: Date
    public var servers: [InventoryEntry]

    public init(mac: String = IdentityStore.defaultComment(), updatedAt: Date = .wholeSecondsNow, servers: [InventoryEntry] = []) {
        self.mac = mac
        self.updatedAt = updatedAt
        self.servers = servers
    }

    /// Inserts the entry, replacing any existing entry with the same alias.
    public mutating func upsert(_ entry: InventoryEntry) {
        if let index = servers.firstIndex(where: { $0.alias == entry.alias }) {
            servers[index] = entry
        } else {
            servers.append(entry)
        }
        updatedAt = .wholeSecondsNow
    }
}

extension Inventory {
    /// Parses an inventory as written by `InventoryStore` or decrypted from a backup.
    public static func decode(_ data: Data) throws -> Inventory {
        try JSON.decoder.decode(Inventory.self, from: data)
    }
}

public enum InventoryStore {
    public static func load(from paths: AgentPaths) throws -> Inventory {
        guard let data = FileManager.default.contents(atPath: paths.inventoryFile.path) else {
            return Inventory()
        }
        return try JSON.decoder.decode(Inventory.self, from: data)
    }

    public static func save(_ inventory: Inventory, to paths: AgentPaths) throws {
        try paths.ensureDirectory()
        try SecureFile.writeAtomically(try JSON.encode(inventory), to: paths.inventoryFile, mode: 0o600)
    }
}

/// Writes `inventory.age` to the backup folder, encrypted with `age` to the
/// emergency public key. This Mac can update it at any time but cannot read it:
/// only the emergency kit decrypts it.
public enum InventoryBackup {
    public static let fileName = "inventory.age"
    public static let readmeName = "README.txt"

    public enum Outcome: Equatable {
        case written(URL)
        /// A backup already exists and this Mac's inventory is empty (a new
        /// Mac, or a fresh setup), so the existing file was left untouched.
        case keptExisting(URL)
        case noBackupFolder
        case noRecoveryKey
        case ageMissing
        case failed(String)

        public var isWritten: Bool {
            if case .written = self { return true }
            return false
        }
    }

    @discardableResult
    public static func export(paths: AgentPaths, settings: AgentSettings? = nil) -> Outcome {
        let settings = settings ?? SettingsStore.load(from: paths)
        guard let folder = settings.backupDirectory else { return .noBackupFolder }
        guard FileManager.default.fileExists(atPath: paths.recoveryPublicKeyFile.path) else { return .noRecoveryKey }
        guard let age = Command.find("age") else { return .ageMissing }

        do {
            if !FileManager.default.fileExists(atPath: folder.path) {
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
            }
            let inventory = try InventoryStore.load(from: paths)
            let target = folder.appendingPathComponent(fileName)
            // Never replace an existing backup with an empty list: on a new Mac
            // that backup is the only copy of the server list.
            if inventory.servers.isEmpty, FileManager.default.fileExists(atPath: target.path) {
                return .keptExisting(target)
            }
            let plaintext = try JSON.encode(inventory)
            let temporary = folder.appendingPathComponent(".\(fileName).\(UUID().uuidString).tmp")
            let result = try Command.run(
                age, ["-R", paths.recoveryPublicKeyFile.path, "-o", temporary.path],
                stdin: plaintext
            )
            guard result.succeeded else {
                try? FileManager.default.removeItem(at: temporary)
                return .failed(result.stderrText.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            guard rename(temporary.path, target.path) == 0 else {
                let reason = String(cString: strerror(errno))
                try? FileManager.default.removeItem(at: temporary)
                return .failed("could not replace \(target.path): \(reason)")
            }
            try Data(readme.utf8).write(to: folder.appendingPathComponent(readmeName), options: .atomic)
            return .written(target)
        } catch {
            return .failed("\(error)")
        }
    }

    /// Plain-text note left next to the backup. It names no server.
    static let readme = """
    touchid-ssh-agent inventory backup
    ==================================

    inventory.age lists the servers where touchid-ssh-agent installed your
    login key and your emergency key. It is encrypted with age to your
    emergency key, so only your emergency kit can read it.

    To read it on any computer with age installed:

        chmod 600 emergency-kit.txt
        age -d -i emergency-kit.txt inventory.age

    age asks for the emergency passphrase. Then log in with:

        ssh -i emergency-kit.txt -p PORT USER@HOST

    """
}

extension Date {
    /// The current time without fractional seconds, which ISO 8601 JSON drops.
    public static var wholeSecondsNow: Date { Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down)) }
}

enum JSON {
    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value) + Data("\n".utf8)
    }
}

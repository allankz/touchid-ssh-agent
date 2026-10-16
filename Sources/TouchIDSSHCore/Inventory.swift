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
    /// CA trust for temporary access, when the user enrolled this server with
    /// `authorize --temporary-access`. Nil means not enrolled.
    public var temporaryAccess: TemporaryAccessEnrollment?

    public init(
        alias: String, destination: String, hostname: String, user: String, port: Int,
        sshConfigFile: String?, loginKeyFingerprint: String, recoveryKeyFingerprint: String,
        authorizedAt: Date, lastAudit: Date? = nil, lastAuditResult: String? = nil, hostKeys: [String]? = nil,
        temporaryAccess: TemporaryAccessEnrollment? = nil
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
        self.temporaryAccess = temporaryAccess
    }

    /// The same server and account: hostname, user and port.
    public func isSameServer(as other: InventoryEntry) -> Bool {
        hostname == other.hostname && user == other.user && port == other.port
    }
}

/// Durable CA trust on one server account. It is part of the inventory backup;
/// nothing in it is secret, and it never describes a live grant.
public struct TemporaryAccessEnrollment: Codable, Equatable {
    /// Stable, opaque identifier of this server account.
    public var targetId: String
    /// The only principal the server's CA line accepts.
    public var principal: String
    /// `ecdsa-sha2-nistp256 BASE64 comment` of the trusted CA.
    public var caPublicKey: String
    public var caFingerprint: String
    /// Options of the `cert-authority` line, exactly as installed.
    public var authorizedKeyOptions: String
    public var enrolledAt: Date
    /// False when the line was installed but a certificate login was never
    /// confirmed; `access` refuses such targets.
    public var verified: Bool
    public var lastAudit: Date?
    public var lastAuditResult: String?
    /// The most recent grant only, so the inventory never grows with history.
    public var lastGrant: GrantSummary?
    /// CA replacement in progress (recovery on a new Mac, or a new CA). Kept
    /// until the old CA's removal is verified on this server.
    public var caRotation: CARotation?
    /// CAs this server trusted before and that were removed from it (a lost
    /// Mac's CA after recovery, or this Mac's previous CA).
    public var retiredCAFingerprints: [String]?

    public init(targetId: String, principal: String, caPublicKey: String, caFingerprint: String,
                authorizedKeyOptions: String, enrolledAt: Date, verified: Bool) {
        self.targetId = targetId
        self.principal = principal
        self.caPublicKey = caPublicKey
        self.caFingerprint = caFingerprint
        self.authorizedKeyOptions = authorizedKeyOptions
        self.enrolledAt = enrolledAt
        self.verified = verified
    }

    /// The CA key blob, but only when it matches the recorded fingerprint.
    public var caBlob: Data? { CAKey(publicKey: caPublicKey, fingerprint: caFingerprint).blob }

    /// Every CA this record says the server may trust: the enrolled one and,
    /// while a replacement is pending, its old and new CAs.
    public var recordedCAs: [CAKey] {
        var keys = [CAKey(publicKey: caPublicKey, fingerprint: caFingerprint)]
        if let rotation = caRotation {
            keys += rotation.oldCAs
            keys.append(CAKey(publicKey: rotation.newCAPublicKey, fingerprint: rotation.newCAFingerprint))
        }
        var seen = Set<String>()
        return keys.filter { seen.insert($0.fingerprint).inserted }
    }
}

/// A CA public key line and its fingerprint, as recorded in the inventory.
public struct CAKey: Codable, Equatable {
    public var publicKey: String
    public var fingerprint: String

    public init(publicKey: String, fingerprint: String) {
        self.publicKey = publicKey
        self.fingerprint = fingerprint
    }

    /// The key blob, only when it matches the recorded fingerprint, so a
    /// damaged record never leads to removing some other key.
    public var blob: Data? {
        guard let blob = SSHKeyFormat.blob(fromPublicKeyLine: publicKey),
              SSHKeyFormat.fingerprint(blob: blob) == fingerprint else { return nil }
        return blob
    }
}

/// Bounded summary of the latest grant for one target. Live paths and process
/// identity stay in the grant's local manifest.
public struct GrantSummary: Codable, Equatable {
    public var grantId: String
    public var serial: UInt64
    public var temporaryKeyFingerprint: String
    public var sshAlias: String
    public var issuedAt: Date
    public var expiresAt: Date
    public var forceCommand: String?
    public var pty: Bool
    public var endedAt: Date?
    /// expired, stopped, crashed, readiness-failed or abandoned.
    public var endReason: String?

    public init(grantId: String, serial: UInt64, temporaryKeyFingerprint: String, sshAlias: String,
                issuedAt: Date, expiresAt: Date, forceCommand: String?, pty: Bool) {
        self.grantId = grantId
        self.serial = serial
        self.temporaryKeyFingerprint = temporaryKeyFingerprint
        self.sshAlias = sshAlias
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.forceCommand = forceCommand
        self.pty = pty
    }
}

/// Progress of replacing one server's CA trust. Written before the server is
/// changed, so an interruption never loses the old CA that still needs removal.
public struct CARotation: Codable, Equatable {
    public enum Step: String, Codable {
        /// Nothing changed on the server yet.
        case planned
        /// The new keys and CA line were added; nothing verified yet.
        case replacementAdded = "replacement-added"
        /// The new login and a certificate through the new CA both worked.
        case replacementVerified = "replacement-verified"
        /// Removal of the retired keys and old CA was attempted.
        case retirementStarted = "retirement-started"
    }

    public var recoveryId: String
    public var oldCAPublicKey: String
    public var oldCAFingerprint: String
    public var newCAPublicKey: String
    public var newCAFingerprint: String
    public var principal: String
    public var authorizedKeyOptions: String
    public var step: Step
    public var updatedAt: Date
    /// More old CAs to remove, when the lost Mac itself left a replacement
    /// unfinished (its previous CA and its own).
    public var extraOldCAs: [CAKey]?

    public init(recoveryId: String, oldCAPublicKey: String, oldCAFingerprint: String, newCAPublicKey: String,
                newCAFingerprint: String, principal: String, authorizedKeyOptions: String, step: Step, updatedAt: Date) {
        self.recoveryId = recoveryId
        self.oldCAPublicKey = oldCAPublicKey
        self.oldCAFingerprint = oldCAFingerprint
        self.newCAPublicKey = newCAPublicKey
        self.newCAFingerprint = newCAFingerprint
        self.principal = principal
        self.authorizedKeyOptions = authorizedKeyOptions
        self.step = step
        self.updatedAt = updatedAt
    }

    /// The old CA key blob, only when it matches its recorded fingerprint, so a
    /// damaged record never leads to removing some other key.
    public var oldCABlob: Data? { CAKey(publicKey: oldCAPublicKey, fingerprint: oldCAFingerprint).blob }

    /// Every old CA this replacement removes.
    public var oldCAs: [CAKey] {
        [CAKey(publicKey: oldCAPublicKey, fingerprint: oldCAFingerprint)] + (extraOldCAs ?? [])
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

    /// Reads the current inventory, applies `change` and saves it, all under
    /// the inventory lock. Every writer goes through here, so a slow command or
    /// a background grant never overwrites newer entries with an old snapshot.
    @discardableResult
    public static func update<T>(_ paths: AgentPaths, _ change: (inout Inventory) throws -> T) throws -> T {
        try paths.ensureDirectory()
        return try FileLock.withLock(paths.inventoryLockFile, timeout: 60) {
            var inventory = try load(from: paths)
            let result = try change(&inventory)
            try save(inventory, to: paths)
            return result
        }
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
    /// `allowEmpty` is for `deauthorize`, which empties the inventory on purpose.
    public static func export(paths: AgentPaths, settings: AgentSettings? = nil, allowEmpty: Bool = false) -> Outcome {
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
            if inventory.servers.isEmpty, !allowEmpty, FileManager.default.fileExists(atPath: target.path) {
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

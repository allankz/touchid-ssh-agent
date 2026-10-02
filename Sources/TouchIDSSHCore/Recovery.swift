import Foundation

public enum RecoveryError: Error, CustomStringConvertible {
    case alreadyConfigured(String)
    case notAPublicKey(String)
    case unsupportedKeyType(String)
    case sshKeygenFailed(String)
    case kitVerificationFailed(String)

    public var description: String {
        switch self {
        case .alreadyConfigured(let fingerprint):
            return "An emergency key is already configured (\(fingerprint)). Use --replace to change it."
        case .notAPublicKey(let detail):
            return "Not an SSH public key: \(detail). Pass the .pub file; the private key must stay off this Mac."
        case .unsupportedKeyType(let type):
            return "Unsupported emergency key type \(type). Use ssh-ed25519 or ssh-rsa, which age can decrypt with."
        case .sshKeygenFailed(let detail):
            return "ssh-keygen failed: \(detail)"
        case .kitVerificationFailed(let detail):
            return "The emergency kit did not verify: \(detail)"
        }
    }
}

/// Public half of the emergency key, stored in `recovery.pub`.
public struct RecoveryKey: Equatable {
    /// Key types that `age` can also use to decrypt the inventory backup.
    public static let supportedTypes: Set<String> = ["ssh-ed25519", "ssh-rsa"]

    public let type: String
    public let blob: Data
    public let comment: String

    public var fingerprint: String { SSHKeyFormat.fingerprint(blob: blob) }
    public var line: String { SSHKeyFormat.authorizedKeyLine(blob: blob, comment: comment) }

    /// Parses an `authorized_keys`-style line and checks that the key type
    /// field matches the type inside the blob.
    public init(line: String) throws {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("-----BEGIN") {
            throw RecoveryError.notAPublicKey("this is a private key")
        }
        let fields = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else {
            throw RecoveryError.notAPublicKey("expected \"TYPE BASE64 [COMMENT]\"")
        }
        let type = String(fields[0])
        guard SSHKeyFormat.keyTypeName(ofBlob: blob) == type else {
            throw RecoveryError.notAPublicKey("the key type does not match its contents")
        }
        guard RecoveryKey.supportedTypes.contains(type) else {
            throw RecoveryError.unsupportedKeyType(type)
        }
        self.type = type
        self.blob = blob
        self.comment = fields.count == 3 ? RemoteKeys.safeComment(String(fields[2])) : "touchid-recovery"
    }
}

public enum RecoveryStore {
    public static func load(from paths: AgentPaths) throws -> RecoveryKey? {
        guard let line = try? String(contentsOf: paths.recoveryPublicKeyFile, encoding: .utf8) else {
            return nil
        }
        return try RecoveryKey(line: line)
    }

    /// Installs `key` as the emergency key. Only the public key is stored.
    @discardableResult
    public static func install(_ key: RecoveryKey, in paths: AgentPaths, replace: Bool) throws -> RecoveryKey {
        if !replace, let existing = try? load(from: paths) {
            throw RecoveryError.alreadyConfigured(existing.fingerprint)
        }
        try paths.ensureDirectory()
        try SecureFile.writeAtomically(Data((key.line + "\n").utf8), to: paths.recoveryPublicKeyFile, mode: 0o644)
        return key
    }

    /// Imports an existing public key file (for example a key you already keep
    /// in a password manager).
    @discardableResult
    public static func importPublicKey(from file: URL, into paths: AgentPaths, replace: Bool) throws -> RecoveryKey {
        let contents: String
        do {
            contents = try String(contentsOf: file, encoding: .utf8)
        } catch {
            throw RecoveryError.notAPublicKey("cannot read \(file.path)")
        }
        guard let firstLine = contents.split(whereSeparator: \.isNewline).first else {
            throw RecoveryError.notAPublicKey("\(file.path) is empty")
        }
        return try install(RecoveryKey(line: String(firstLine)), in: paths, replace: replace)
    }
}

/// Random emergency passphrases: 6 groups of 4 characters from an alphabet
/// without look-alikes (no 0/o, 1/l/i), about 119 bits.
public enum Passphrase {
    public static let alphabet = Array("23456789abcdefghjkmnpqrstuvwxyz")

    public static func generate() -> String {
        var generator = SystemRandomNumberGenerator()
        let groups = (0..<6).map { _ in
            String((0..<4).map { _ in alphabet[Int.random(in: 0..<alphabet.count, using: &generator)] })
        }
        return groups.joined(separator: "-")
    }

    public static let minimumCustomLength = 16
}

/// The emergency kit is one text file: the passphrase-protected OpenSSH private
/// key first (so `ssh -i` and `age -i` accept the file as is), then plain-text
/// recovery instructions after the END line, which both tools ignore.
public struct EmergencyKit {
    public let file: URL
    public let recoveryKey: RecoveryKey
}

public enum EmergencyKitBuilder {
    public static let kitFileName = "emergency-kit.txt"
    static let keyFileName = "emergency-key"
    /// ssh-keygen falls back to an askpass helper when these are set, which
    /// would bypass the passphrase written to its stdin.
    public static let askpassVariables: Set<String> = ["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY"]

    public struct Details {
        public var createdAt: Date
        /// Short name of this Mac, used in the key comment.
        public var macName: String
        public var loginKeyFingerprint: String?
        /// Backup folder as shown to the user (may start with ~).
        public var backupFolder: String?

        public init(createdAt: Date = Date(), macName: String, loginKeyFingerprint: String?, backupFolder: String?) {
            self.createdAt = createdAt
            self.macName = macName
            self.loginKeyFingerprint = loginKeyFingerprint
            self.backupFolder = backupFolder
        }

        var createdOn: String {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyy-MM-dd"
            return "\(formatter.string(from: createdAt)) on \(macName)"
        }
    }

    /// Generates the emergency key and writes the kit into `paths.kitDirectory`.
    /// Nothing is installed yet: call `finalize` after the user saved the kit,
    /// or `discard` to abort.
    public static func build(passphrase: String, details: Details, paths: AgentPaths) throws -> EmergencyKit {
        try paths.ensureDirectory()
        discard(paths: paths)
        guard mkdir(paths.kitDirectory.path, 0o700) == 0 else {
            throw RecoveryError.sshKeygenFailed("cannot create \(paths.kitDirectory.path)")
        }
        do {
            let keyFile = paths.kitDirectory.appendingPathComponent(keyFileName)
            let comment = RemoteKeys.safeComment("touchid-recovery@\(details.macName)")
            let generated = try Command.runWithoutTerminal(
                "/usr/bin/ssh-keygen",
                ["-q", "-t", "ed25519", "-a", "200", "-C", comment, "-f", keyFile.path],
                stdin: Data("\(passphrase)\n\(passphrase)\n".utf8),
                removingEnvironment: askpassVariables
            )
            guard generated.succeeded,
                  let publicLine = try? String(contentsOf: keyFile.appendingPathExtension("pub"), encoding: .utf8) else {
                throw RecoveryError.sshKeygenFailed(generated.stderrText)
            }
            let recoveryKey = try RecoveryKey(line: publicLine)

            let privateKey = try String(contentsOf: keyFile, encoding: .utf8)
            let kitFile = paths.kitDirectory.appendingPathComponent(kitFileName)
            let kitText = privateKey + "\n" + instructions(recoveryKey: recoveryKey, details: details)
            try SecureFile.writeAtomically(Data(kitText.utf8), to: kitFile, mode: 0o600)
            SecureFile.erase(keyFile)
            SecureFile.erase(keyFile.appendingPathExtension("pub"))

            // The kit file itself must open with the passphrase before anyone relies on it.
            try verify(kitFile: kitFile, passphrase: passphrase, expected: recoveryKey)
            return EmergencyKit(file: kitFile, recoveryKey: recoveryKey)
        } catch {
            discard(paths: paths)
            throw error
        }
    }

    /// Decrypts the kit with `passphrase` and checks it yields `expected`.
    public static func verify(kitFile: URL, passphrase: String, expected: RecoveryKey) throws {
        let derived = try Command.runWithoutTerminal(
            "/usr/bin/ssh-keygen", ["-y", "-f", kitFile.path],
            stdin: Data("\(passphrase)\n".utf8),
            removingEnvironment: askpassVariables
        )
        guard derived.succeeded else {
            throw RecoveryError.kitVerificationFailed(derived.stderrText.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let line = derived.stdoutText.split(whereSeparator: \.isNewline)
            .first { $0.hasPrefix(expected.type) }.map(String.init) ?? ""
        guard let derivedKey = try? RecoveryKey(line: line), derivedKey.blob == expected.blob else {
            throw RecoveryError.kitVerificationFailed("the kit does not contain the expected key")
        }
    }

    /// Installs the emergency public key and erases the kit scratch directory,
    /// so no copy of the private key stays on this Mac.
    @discardableResult
    public static func finalize(_ kit: EmergencyKit, paths: AgentPaths, replace: Bool) throws -> RecoveryKey {
        defer { discard(paths: paths) }
        return try RecoveryStore.install(kit.recoveryKey, in: paths, replace: replace)
    }

    public static func discard(paths: AgentPaths) {
        if FileManager.default.fileExists(atPath: paths.kitDirectory.path) {
            SecureFile.eraseDirectory(paths.kitDirectory)
        }
    }

    static func instructions(recoveryKey: RecoveryKey, details: Details) -> String {
        let login = details.loginKeyFingerprint ?? "(none yet)"
        let backup = details.backupFolder.map { "\($0)/\(InventoryBackup.fileName)" }
            ?? "none configured: keep your own list of servers"
        return """

        TOUCHID-SSH-AGENT EMERGENCY KIT
        ===============================

        The block above is your emergency SSH private key, encrypted with your
        emergency passphrase. Keep this file outside your Mac (password manager,
        USB drive, an email to yourself) and keep the passphrase somewhere else.

        Created:           \(details.createdOn)
        Emergency key:     \(recoveryKey.fingerprint) (\(recoveryKey.type))
        Login key (Mac):   \(login)
        Inventory backup:  \(backup)

        IF YOUR MAC IS LOST, STOLEN OR BROKEN

        On a Mac (the quick way):
        1. Install touchid-ssh-agent:
             git clone https://github.com/allankz/touchid-ssh-agent
             cd touchid-ssh-agent && make install
        2. Run it with this file:
             touchid-ssh-agent recover emergency-kit.txt
           It opens the inventory, installs the new Mac's keys on every
           server, removes the lost Mac's key and this emergency key, and
           finishes with an audit. For security it asks for the passphrase
           twice: once to open the inventory, once to load this key.

        On any other computer, with OpenSSH and age (https://age-encryption.org):
        1. Save this file as emergency-kit.txt and run:
             chmod 600 emergency-kit.txt
        2. Download inventory.age from the backup folder above and read the
           server list (asks for the passphrase):
             age -d -i emergency-kit.txt inventory.age
        3. Log in to each server (asks for the passphrase):
             ssh -i emergency-kit.txt -p PORT USER@HOST
        4. On each server, remove the line with the lost Mac's login key
           (fingerprint above) from ~/.ssh/authorized_keys. To see each
           line's fingerprint: ssh-keygen -lf ~/.ssh/authorized_keys
        5. On your new Mac run `touchid-ssh-agent setup`, which creates a new
           kit, then `touchid-ssh-agent authorize` for every server.
        6. Remove this emergency key from the servers afterwards: once it has
           been used, treat it as exposed.

        To check now and then that this kit still opens every server, without
        changing anything:
             touchid-ssh-agent recovery test emergency-kit.txt

        """
    }
}

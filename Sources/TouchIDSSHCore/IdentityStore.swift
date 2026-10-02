import CryptoKit
import Darwin
import Foundation
import Security

public enum IdentityStoreError: Error, CustomStringConvertible {
    case secureEnclaveUnavailable
    case identityAlreadyExists(URL)
    case insecureDirectory(String)
    case accessControl(String)
    case invalidKeyFile(String)
    case deviceLocked

    public var description: String {
        switch self {
        case .secureEnclaveUnavailable:
            return "This Mac has no Secure Enclave available."
        case .identityAlreadyExists(let url):
            return "An identity already exists at \(url.path). Delete it before creating another one."
        case .insecureDirectory(let reason):
            return "Insecure directory: \(reason)"
        case .accessControl(let reason):
            return "Could not create the access control policy: \(reason)"
        case .invalidKeyFile(let reason):
            return "Invalid key file: \(reason)"
        case .deviceLocked:
            return "The Mac is locked; unlock the screen and try again."
        }
    }
}

/// File locations used by the agent. Everything lives in one private directory.
public struct AgentPaths: Equatable {
    public static let environmentVariable = "TOUCHID_SSH_AGENT_DIR"

    public let directory: URL

    public init(directory: URL) {
        self.directory = directory.standardizedFileURL
    }

    public static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".touchid-ssh-agent")
    }

    /// `$TOUCHID_SSH_AGENT_DIR` when set, otherwise `~/.touchid-ssh-agent`.
    public static func fromEnvironment() -> AgentPaths {
        if let custom = ProcessInfo.processInfo.environment[environmentVariable], !custom.isEmpty {
            return AgentPaths(directory: URL(fileURLWithPath: (custom as NSString).expandingTildeInPath))
        }
        return AgentPaths(directory: defaultDirectory)
    }

    public var isDefault: Bool { directory == AgentPaths.defaultDirectory.standardizedFileURL }

    /// Secure Enclave-wrapped key. Only this Mac's Secure Enclave can use it.
    public var keyFile: URL { directory.appendingPathComponent("identity.se") }
    public var publicKeyFile: URL { directory.appendingPathComponent("id_ecdsa_se.pub") }
    public var socket: URL { directory.appendingPathComponent("agent.sock") }
    public var logFile: URL { directory.appendingPathComponent("agent.log") }
    /// Public half of the emergency key. Its private half lives only in the kit.
    public var recoveryPublicKeyFile: URL { directory.appendingPathComponent("recovery.pub") }
    public var settingsFile: URL { directory.appendingPathComponent("config.json") }
    public var inventoryFile: URL { directory.appendingPathComponent("inventory.json") }
    /// Scratch space for building the emergency kit; erased once it is saved.
    public var kitDirectory: URL { directory.appendingPathComponent("kit") }

    /// Path suitable for ssh_config, using `~` when inside the home directory.
    public func displayPath(_ url: URL) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        return path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }

    /// Creates the directory with mode 0700 or verifies an existing one: it must be
    /// a real directory owned by the current user. Group/other bits are removed.
    public func ensureDirectory() throws {
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            guard errno == ENOENT else {
                throw IdentityStoreError.insecureDirectory(String(cString: strerror(errno)))
            }
            guard mkdir(directory.path, 0o700) == 0 else {
                throw IdentityStoreError.insecureDirectory(String(cString: strerror(errno)))
            }
            return
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw IdentityStoreError.insecureDirectory("\(directory.path) is not a regular directory")
        }
        guard info.st_uid == getuid() else {
            throw IdentityStoreError.insecureDirectory("\(directory.path) belongs to another user")
        }
        if info.st_mode & 0o077 != 0 {
            guard chmod(directory.path, 0o700) == 0 else {
                throw IdentityStoreError.insecureDirectory(String(cString: strerror(errno)))
            }
        }
    }
}

/// How the Secure Enclave decides whether a signature may happen.
public enum BiometryPolicy: String, CaseIterable {
    /// Touch ID with the fingerprints enrolled today. Enrolling or removing a
    /// fingerprint permanently invalidates the key. Default.
    case currentSet = "current-set"
    /// Touch ID with any fingerprint enrolled now or later.
    case any

    var flags: SecAccessControlCreateFlags {
        switch self {
        case .currentSet: return [.privateKeyUsage, .biometryCurrentSet]
        case .any: return [.privateKeyUsage, .biometryAny]
        }
    }
}

/// An identity loaded from disk. Holds only the Secure Enclave-wrapped blob and
/// the public key; there is no private key material in this process.
public struct StoredIdentity {
    public let wrappedKey: Data
    public let publicKey: P256.Signing.PublicKey
    public let comment: String

    public var publicKeyBlob: Data { SSHKeyFormat.publicKeyBlob(publicKey) }
    public var fingerprint: String { SSHKeyFormat.fingerprint(blob: publicKeyBlob) }
    public var authorizedKeyLine: String {
        SSHKeyFormat.authorizedKeyLine(blob: publicKeyBlob, comment: comment)
    }
}

public enum IdentityStore {
    /// Short host name of this Mac, e.g. "studio" for "studio.local".
    public static func macName() -> String {
        ProcessInfo.processInfo.hostName
            .replacingOccurrences(of: ".local", with: "")
            .split(separator: ".").first.map(String.init) ?? "mac"
    }

    public static func defaultComment() -> String {
        "touchid-ssh-agent@\(macName())"
    }

    /// Creates a new Secure Enclave key protected by Touch ID. The key never
    /// leaves the Secure Enclave; the file holds a blob only it can unwrap.
    @discardableResult
    public static func create(
        in paths: AgentPaths,
        policy: BiometryPolicy,
        comment: String = defaultComment()
    ) throws -> StoredIdentity {
        try create(in: paths, flags: policy.flags, comment: comment)
    }

    /// Test-only: a Secure Enclave key that signs without any prompt, so the
    /// automated suite can exercise the full protocol. Refuses the real directory.
    @_spi(Testing)
    @discardableResult
    public static func createWithoutUserPresenceForTesting(in paths: AgentPaths) throws -> StoredIdentity {
        guard !paths.isDefault else {
            throw IdentityStoreError.insecureDirectory("test keys cannot use the default directory")
        }
        return try create(in: paths, flags: [.privateKeyUsage], comment: "touchid-ssh-agent-test")
    }

    private static func create(
        in paths: AgentPaths,
        flags: SecAccessControlCreateFlags,
        comment: String
    ) throws -> StoredIdentity {
        guard SecureEnclave.isAvailable else { throw IdentityStoreError.secureEnclaveUnavailable }
        try paths.ensureDirectory()
        guard !FileManager.default.fileExists(atPath: paths.keyFile.path) else {
            throw IdentityStoreError.identityAlreadyExists(paths.keyFile)
        }

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error
        ) else {
            let reason = error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown error"
            throw IdentityStoreError.accessControl(reason)
        }

        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch let error as NSError where error.domain == NSOSStatusErrorDomain
            && error.code == Int(errSecInteractionNotAllowed) {
            throw IdentityStoreError.deviceLocked
        }
        let identity = StoredIdentity(
            wrappedKey: key.dataRepresentation,
            publicKey: key.publicKey,
            comment: DisplayText.sanitize(comment, maxLength: 120)
        )
        // Without a key file, any .pub left behind is stale.
        try? FileManager.default.removeItem(at: paths.publicKeyFile)
        try writeFile(paths.keyFile, contents: identity.wrappedKey, mode: 0o600)
        try writeFile(paths.publicKeyFile, contents: Data((identity.authorizedKeyLine + "\n").utf8), mode: 0o644)
        return identity
    }

    /// Loads the identity, or returns nil when none has been created.
    /// Reading the public key does not require Touch ID.
    public static func load(from paths: AgentPaths) throws -> StoredIdentity? {
        guard let wrapped = FileManager.default.contents(atPath: paths.keyFile.path) else {
            return nil
        }
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped)
        } catch {
            throw IdentityStoreError.invalidKeyFile("\(error)")
        }
        let publicKeyBlob = SSHKeyFormat.publicKeyBlob(key.publicKey)
        // The comment comes from the .pub file only if it describes this same key.
        var comment = defaultComment()
        if let line = try? String(contentsOf: paths.publicKeyFile, encoding: .utf8),
           SSHKeyFormat.blob(fromPublicKeyLine: line) == publicKeyBlob {
            let fields = line.trimmingCharacters(in: .whitespacesAndNewlines)
                .split(separator: " ", maxSplits: 2)
            if fields.count == 3 { comment = String(fields[2]) }
        }
        return StoredIdentity(wrappedKey: wrapped, publicKey: key.publicKey, comment: comment)
    }

    /// Deletes the identity. The Secure Enclave keeps no copy, so once the
    /// wrapped blob is gone the key is unrecoverable.
    public static func delete(from paths: AgentPaths) throws {
        SecureFile.erase(paths.keyFile)
        if FileManager.default.fileExists(atPath: paths.publicKeyFile.path) {
            try FileManager.default.removeItem(at: paths.publicKeyFile)
        }
    }

    private static func writeFile(_ url: URL, contents: Data, mode: mode_t) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else {
            throw IdentityStoreError.invalidKeyFile("\(url.path): \(String(cString: strerror(errno)))")
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: contents)
        try handle.synchronize()
        fchmod(fd, mode)
    }
}

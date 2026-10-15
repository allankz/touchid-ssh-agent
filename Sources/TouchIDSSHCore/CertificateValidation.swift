import CryptoKit
import Darwin
import Foundation

/// A short-lived certificate that exists only to prove servers accept the CA,
/// for `authorize --temporary-access` and `recover`. Its key stays in this
/// process; its files live in a private temporary directory erased by `stop`.
/// It is never published as an access grant, and its forced command means it
/// could not run anything even if it were used for more than authentication.
public final class CertificateValidation {
    public let directory: URL
    public let issued: IssuedCertificate
    public let principals: [String]
    private let agent: TemporaryAgent
    private var stopped = false

    /// Signs one certificate for `principals` with `sign` (one Touch ID with a
    /// real CA), valid for `lifetime` seconds.
    public init(caBlob: Data, principals: [String], users: Set<String>, lifetime: UInt64, paths: AgentPaths,
                sign: (Data) throws -> Data) throws {
        var template = Array((NSTemporaryDirectory() + "tidval-XXXXXX").utf8CString)
        guard let created = mkdtemp(&template) else { throw CocoaError(.fileWriteUnknown) }
        directory = URL(fileURLWithPath: String(cString: created))
        do {
            let now = UInt64(Date().timeIntervalSince1970)
            let serial = try CertificateSerial.next(paths: paths)
            issued = try CertificateIssuer.issue(
                ca: caBlob, serial: serial, keyID: CertificateIssuer.keyID(prefix: "validation", at: Date(), serial: serial),
                principals: principals, validAfter: now - CertificateIssuer.clockSkewMargin, validBefore: now + lifetime,
                criticalOptions: [.forceCommand("true")], sign: sign)
            self.principals = principals
            let files = GrantFiles(directory: directory)
            let comment = "touchid-ssh-agent-validation"
            try SecureFile.writeAtomically(Data((Ed25519SSH.publicKeyLine(issued.publicKeyBlob, comment: comment) + "\n").utf8),
                                           to: files.publicKey, mode: 0o600)
            try SecureFile.writeAtomically(Data((SSHCertificate.publicKeyLine(blob: issued.blob, comment: comment) + "\n").utf8),
                                           to: files.certificate, mode: 0o600)
            agent = TemporaryAgent(socketPath: files.agentSocket.path, credential: issued,
                                   deadline: GrantDeadline(expiresAt: TimeInterval(now + lifetime)),
                                   allowedUsers: users, comment: comment, log: nil, logName: "validation")
            try agent.start()
        } catch {
            SecureFile.eraseDirectory(directory)
            throw error
        }
    }

    deinit { stop() }

    public var isExpired: Bool { agent.deadline.isExpired || agent.deadline.remaining < 60 }

    /// Authenticates to one server with the certificate, pinning `hostKeys`,
    /// and closes the connection right after authentication.
    public func check(hostname: String, user: String, port: Int, principal: String, hostKeys: [String]) -> CertificateLoginCheck.Outcome {
        guard !hostKeys.isEmpty else { return .failed("no recorded host key to check the server against") }
        let alias = "check-access-00000000-\(String(format: "%012x", UInt64.random(in: 0...0xffff_ffff_ffff)))"
        let target = AccessTarget(requested: alias, inventoryAlias: alias, targetId: principal, principal: principal,
                                  hostname: hostname, user: user, port: port, hostKeys: hostKeys, sshAlias: alias)
        let request = AccessRequest(grantId: "00000000-000000000000", dataDirectory: directory.path, caFingerprint: "",
                                    targets: [target], permissions: AccessPermissions(),
                                    requestedAt: UInt64(Date().timeIntervalSince1970), duration: 60)
        let files = GrantFiles(directory: directory)
        do {
            try SecureFile.writeAtomically(Data(GrantSSHConfig.knownHosts(request).utf8), to: files.knownHosts, mode: 0o600)
            try SecureFile.writeAtomically(Data(try GrantSSHConfig.render(request, files: files).utf8), to: files.sshConfig, mode: 0o600)
        } catch {
            return .failed("\(error)")
        }
        return CertificateLoginCheck.run(configFile: files.sshConfig, alias: alias, keyFingerprint: issued.fingerprint)
    }

    public func stop() {
        guard !stopped else { return }
        stopped = true
        agent.stop()
        SecureFile.eraseDirectory(directory)
    }
}

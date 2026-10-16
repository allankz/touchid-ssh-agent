import CryptoKit
import Darwin
import Foundation
import Security

/// The CA that signs temporary-access certificates. It is a second Secure
/// Enclave key, separate from the login key, always protected by Touch ID with
/// the fingerprints enrolled today (`current-set`). Servers trust its public key
/// through a scoped `cert-authority` line; it is never offered on any socket.
public enum CertificateAuthorityStore {
    public static func defaultComment() -> String {
        "touchid-ssh-agent-ca@\(IdentityStore.macName())"
    }

    /// Creates the CA. Fails if one already exists: replacing it would orphan
    /// the trust lines servers already hold.
    @discardableResult
    public static func create(in paths: AgentPaths) throws -> StoredIdentity {
        try IdentityStore.createKey(in: paths, keyFile: paths.caKeyFile, publicKeyFile: paths.caPublicKeyFile,
                                    flags: BiometryPolicy.currentSet.flags, comment: defaultComment())
    }

    /// Test-only: a CA that signs without any prompt. Refuses the real directory.
    @_spi(Testing)
    @discardableResult
    public static func createWithoutUserPresenceForTesting(in paths: AgentPaths) throws -> StoredIdentity {
        guard !paths.isDefault else {
            throw IdentityStoreError.insecureDirectory("test keys cannot use the default directory")
        }
        return try IdentityStore.createKey(in: paths, keyFile: paths.caKeyFile, publicKeyFile: paths.caPublicKeyFile,
                                           flags: [.privateKeyUsage], comment: "touchid-ssh-agent-ca-test")
    }

    /// Loads the CA, or nil when this Mac has none yet. No Touch ID needed.
    public static func load(from paths: AgentPaths) throws -> StoredIdentity? {
        try IdentityStore.loadKey(keyFile: paths.caKeyFile, publicKeyFile: paths.caPublicKeyFile,
                                  defaultComment: defaultComment())
    }

    /// The existing CA, or a new one. `created` tells which.
    public static func loadOrCreate(in paths: AgentPaths) throws -> (ca: StoredIdentity, created: Bool) {
        if let existing = try load(from: paths) { return (existing, false) }
        return (try create(in: paths), true)
    }
}

/// Certificate serial numbers: a counter in `ca.serial`, incremented under a
/// lock so concurrent issuers never reuse a number.
public enum CertificateSerial {
    public static func next(paths: AgentPaths) throws -> UInt64 {
        try paths.ensureDirectory()
        return try FileLock.withLock(paths.caSerialLockFile, timeout: 30) {
            var current: UInt64 = 0
            if let text = try? String(contentsOf: paths.caSerialFile, encoding: .utf8) {
                current = UInt64(text.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            }
            guard current < UInt64.max - 1 else { throw SSHCertificateError.invalidValidity }
            let next = current + 1
            try SecureFile.writeAtomically(Data("\(next)\n".utf8), to: paths.caSerialFile, mode: 0o600)
            return next
        }
    }
}

/// A certificate and the in-memory private key it certifies. The private key is
/// never serialized: it lives only as long as this value.
public struct IssuedCertificate {
    public let privateKey: Curve25519.Signing.PrivateKey
    public let certificate: SSHCertificate
    public let blob: Data

    public var publicKeyBlob: Data { Ed25519SSH.publicKeyBlob(privateKey.publicKey) }
    /// Fingerprint of the certified key, as `ssh -v` prints it for the certificate.
    public var fingerprint: String { SSHKeyFormat.fingerprint(blob: publicKeyBlob) }
}

public enum CertificateIssuer {
    /// Five minutes of tolerance for servers whose clock runs behind this Mac's.
    public static let clockSkewMargin: UInt64 = 300

    /// `access-YYYYMMDD-HHMM-<serial>` (UTC), shown in server logs.
    public static func keyID(prefix: String, at date: Date, serial: UInt64) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd-HHmm"
        return "\(prefix)-\(formatter.string(from: date))-\(serial)"
    }

    /// Generates a fresh Ed25519 key in memory, builds the certificate from the
    /// given fields and has `sign` produce the CA signature over it. The result
    /// is checked against the CA public key before it is returned.
    public static func issue(
        ca caPublicKeyBlob: Data, privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
        serial: UInt64, keyID: String, principals: [String], validAfter: UInt64, validBefore: UInt64,
        criticalOptions: [CertificateOption] = [], extensions: [CertificateOption] = [],
        sign: (Data) throws -> Data
    ) throws -> IssuedCertificate {
        let certificate = SSHCertificate(
            nonce: SSHCertificate.randomNonce(), publicKey: privateKey.publicKey.rawRepresentation, serial: serial,
            keyID: keyID, principals: principals, validAfter: validAfter, validBefore: validBefore,
            criticalOptions: criticalOptions, extensions: extensions, signatureKey: caPublicKeyBlob)
        let toBeSigned = try certificate.toBeSigned()
        let signature = try sign(toBeSigned)
        let blob = try certificate.encoded(signature: signature)
        guard SSHCertificate.verifySignature(blob: blob) else { throw SSHCertificateError.invalidSignature }
        var signed = certificate
        signed.signature = signature
        return IssuedCertificate(privateKey: privateKey, certificate: signed, blob: blob)
    }
}

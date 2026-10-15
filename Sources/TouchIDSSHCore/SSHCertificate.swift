import CryptoKit
import Foundation

public enum SSHCertificateError: Error, Equatable, CustomStringConvertible {
    case invalidNonce
    case invalidKey
    case unsupportedType(String)
    case invalidKeyID
    case noPrincipals
    case invalidPrincipal(String)
    case duplicatePrincipal(String)
    case invalidValidity
    case invalidOption(String)
    case duplicateOption(String)
    case unsortedOptions
    case reservedNotEmpty
    case invalidSignature
    case tooLarge

    public var description: String {
        switch self {
        case .invalidNonce: return "certificate nonce must be 32 bytes"
        case .invalidKey: return "certificate key is not an Ed25519 public key"
        case .unsupportedType(let type): return "unsupported certificate type \(type)"
        case .invalidKeyID: return "invalid certificate key ID"
        case .noPrincipals: return "a certificate needs at least one principal"
        case .invalidPrincipal(let name): return "invalid principal \(name)"
        case .duplicatePrincipal(let name): return "duplicate principal \(name)"
        case .invalidValidity: return "the validity interval must be finite and not empty"
        case .invalidOption(let name): return "invalid certificate option \(name)"
        case .duplicateOption(let name): return "duplicate certificate option \(name)"
        case .unsortedOptions: return "certificate options must be sorted by name"
        case .reservedNotEmpty: return "the reserved certificate field must be empty"
        case .invalidSignature: return "the certificate signature does not verify"
        case .tooLarge: return "certificate too large"
        }
    }
}

/// Encoding of Ed25519 keys and signatures in the OpenSSH formats (RFC 8709).
public enum Ed25519SSH {
    public static let keyType = "ssh-ed25519"

    /// `string "ssh-ed25519" || string pk` (32 bytes).
    public static func publicKeyBlob(raw: Data) -> Data {
        var writer = SSHWriter()
        writer.writeString(keyType)
        writer.writeString(raw)
        return writer.data
    }

    public static func publicKeyBlob(_ key: Curve25519.Signing.PublicKey) -> Data {
        publicKeyBlob(raw: key.rawRepresentation)
    }

    /// `string "ssh-ed25519" || string signature` (64 bytes).
    public static func signatureBlob(_ signature: Data) -> Data {
        var writer = SSHWriter()
        writer.writeString(keyType)
        writer.writeString(signature)
        return writer.data
    }

    public static func rawPublicKey(fromBlob blob: Data) throws -> Data {
        var reader = SSHReader(blob)
        guard try reader.readUTF8() == keyType else { throw SSHCertificateError.invalidKey }
        let raw = try reader.readString()
        try reader.expectEnd()
        guard raw.count == 32 else { throw SSHCertificateError.invalidKey }
        return raw
    }

    public static func rawSignature(fromBlob blob: Data) throws -> Data {
        var reader = SSHReader(blob)
        guard try reader.readUTF8() == keyType else { throw SSHCertificateError.invalidSignature }
        let raw = try reader.readString()
        try reader.expectEnd()
        guard raw.count == 64 else { throw SSHCertificateError.invalidSignature }
        return raw
    }
}

/// One critical option or extension: a name and its raw `data` field.
public struct CertificateOption: Equatable {
    public let name: String
    public let data: Data

    public init(name: String, data: Data) {
        self.name = name
        self.data = data
    }

    /// `force-command`: the data field holds the command as a nested string.
    public static func forceCommand(_ command: String) -> CertificateOption {
        var writer = SSHWriter()
        writer.writeString(command)
        return CertificateOption(name: "force-command", data: writer.data)
    }

    /// `source-address`: a nested string of comma-separated CIDR ranges.
    public static func sourceAddress(_ ranges: String) -> CertificateOption {
        var writer = SSHWriter()
        writer.writeString(ranges)
        return CertificateOption(name: "source-address", data: writer.data)
    }

    /// Extensions such as `permit-pty` carry no data.
    public static func flag(_ name: String) -> CertificateOption {
        CertificateOption(name: name, data: Data())
    }

    /// The nested string inside `data`, for options that carry one.
    public var stringValue: String? {
        var reader = SSHReader(data)
        guard let value = try? reader.readUTF8(), reader.isAtEnd else { return nil }
        return value
    }
}

/// An OpenSSH user certificate for an Ed25519 key (`ssh-ed25519-cert-v01@openssh.com`,
/// PROTOCOL.certkeys), signed by a CA. Every field is validated before encoding,
/// so a certificate this type builds is always one OpenSSH accepts as well formed.
public struct SSHCertificate: Equatable {
    public static let type = "ssh-ed25519-cert-v01@openssh.com"
    public static let userCertificate: UInt32 = 1
    public static let maxBlobLength = 16 * 1024
    static let knownCriticalOptions: Set<String> = ["force-command", "source-address", "verify-required"]
    static let knownExtensions: Set<String> = [
        "no-touch-required", "permit-X11-forwarding", "permit-agent-forwarding",
        "permit-port-forwarding", "permit-pty", "permit-user-rc",
    ]

    public var nonce: Data
    /// Raw 32-byte Ed25519 public key being certified.
    public var publicKey: Data
    public var serial: UInt64
    public var certificateType: UInt32 = SSHCertificate.userCertificate
    public var keyID: String
    public var principals: [String]
    public var validAfter: UInt64
    public var validBefore: UInt64
    public var criticalOptions: [CertificateOption]
    public var extensions: [CertificateOption]
    /// The CA's public key blob.
    public var signatureKey: Data
    /// The CA's signature blob; nil until signed.
    public var signature: Data?

    public init(
        nonce: Data, publicKey: Data, serial: UInt64, keyID: String, principals: [String],
        validAfter: UInt64, validBefore: UInt64, criticalOptions: [CertificateOption] = [],
        extensions: [CertificateOption] = [], signatureKey: Data
    ) {
        self.nonce = nonce
        self.publicKey = publicKey
        self.serial = serial
        self.keyID = keyID
        self.principals = principals
        self.validAfter = validAfter
        self.validBefore = validBefore
        self.criticalOptions = criticalOptions
        self.extensions = extensions
        self.signatureKey = signatureKey
    }

    /// A fresh 32-byte nonce from the system generator.
    public static func randomNonce() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    /// Principal names that fit inside an authorized_keys `principals="..."` list.
    public static func isValidPrincipal(_ name: String) -> Bool {
        !name.isEmpty && name.count <= 64
            && name.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@-").contains($0) }
    }

    /// The bytes the CA signs: every field from the type string through the
    /// signature key. Throws when any field is invalid.
    public func toBeSigned() throws -> Data {
        guard nonce.count == 32 else { throw SSHCertificateError.invalidNonce }
        guard publicKey.count == 32 else { throw SSHCertificateError.invalidKey }
        guard certificateType == SSHCertificate.userCertificate else { throw SSHCertificateError.unsupportedType("host") }
        guard !keyID.isEmpty, keyID.count <= 256,
              keyID.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7f }) else {
            throw SSHCertificateError.invalidKeyID
        }
        guard !principals.isEmpty, principals.count <= 256 else { throw SSHCertificateError.noPrincipals }
        var seen = Set<String>()
        for principal in principals {
            guard SSHCertificate.isValidPrincipal(principal) else { throw SSHCertificateError.invalidPrincipal(principal) }
            guard seen.insert(principal).inserted else { throw SSHCertificateError.duplicatePrincipal(principal) }
        }
        guard validAfter < validBefore, validBefore != UInt64.max else { throw SSHCertificateError.invalidValidity }
        try SSHCertificate.validate(criticalOptions, known: SSHCertificate.knownCriticalOptions, nested: true)
        try SSHCertificate.validate(extensions, known: SSHCertificate.knownExtensions, nested: false)
        guard SSHKeyFormat.keyTypeName(ofBlob: signatureKey) != nil else { throw SSHCertificateError.invalidKey }

        var principalList = SSHWriter()
        for principal in principals { principalList.writeString(principal) }

        var writer = SSHWriter()
        writer.writeString(SSHCertificate.type)
        writer.writeString(nonce)
        writer.writeString(publicKey)
        writer.writeUInt64(serial)
        writer.writeUInt32(certificateType)
        writer.writeString(keyID)
        writer.writeString(principalList.data)
        writer.writeUInt64(validAfter)
        writer.writeUInt64(validBefore)
        writer.writeString(SSHCertificate.encode(SSHCertificate.sorted(criticalOptions)))
        writer.writeString(SSHCertificate.encode(SSHCertificate.sorted(extensions)))
        writer.writeString(Data()) // reserved
        writer.writeString(signatureKey)
        guard writer.data.count < SSHCertificate.maxBlobLength else { throw SSHCertificateError.tooLarge }
        return writer.data
    }

    /// The complete certificate blob with `signature` appended.
    public func encoded(signature: Data) throws -> Data {
        var writer = SSHWriter()
        writer.writeString(signature)
        return try toBeSigned() + writer.data
    }

    /// `type base64 comment`, the format of `-cert.pub` files.
    public static func publicKeyLine(blob: Data, comment: String) -> String {
        SSHKeyFormat.authorizedKeyLine(blob: blob, comment: comment)
    }

    static func validate(_ options: [CertificateOption], known: Set<String>, nested: Bool) throws {
        var names = Set<String>()
        for option in options {
            guard known.contains(option.name) else { throw SSHCertificateError.invalidOption(option.name) }
            guard names.insert(option.name).inserted else { throw SSHCertificateError.duplicateOption(option.name) }
            let needsValue = nested && option.name != "verify-required"
            if needsValue {
                guard let value = option.stringValue, !value.isEmpty, !value.contains("\0") else {
                    throw SSHCertificateError.invalidOption(option.name)
                }
            } else if !option.data.isEmpty {
                throw SSHCertificateError.invalidOption(option.name)
            }
        }
    }

    /// OpenSSH requires options in lexical (byte) order of their names.
    static func sorted(_ options: [CertificateOption]) -> [CertificateOption] {
        options.sorted { Array($0.name.utf8).lexicographicallyPrecedes(Array($1.name.utf8)) }
    }

    static func encode(_ options: [CertificateOption]) -> Data {
        var writer = SSHWriter()
        for option in options {
            writer.writeString(option.name)
            writer.writeString(option.data)
        }
        return writer.data
    }

    static func decodeOptions(_ data: Data) throws -> [CertificateOption] {
        var reader = SSHReader(data)
        var options: [CertificateOption] = []
        var previous: [UInt8]?
        while !reader.isAtEnd {
            let name = try reader.readUTF8()
            let value = try reader.readString()
            let bytes = Array(name.utf8)
            if let previous {
                guard previous != bytes else { throw SSHCertificateError.duplicateOption(name) }
                guard previous.lexicographicallyPrecedes(bytes) else { throw SSHCertificateError.unsortedOptions }
            }
            previous = bytes
            options.append(CertificateOption(name: name, data: value))
        }
        return options
    }

    /// Parses an Ed25519 user certificate blob. The fields are checked for shape
    /// only; call `verifySignature` to check the CA signature.
    public static func parse(_ blob: Data) throws -> (certificate: SSHCertificate, signedLength: Int) {
        guard blob.count <= maxBlobLength else { throw SSHCertificateError.tooLarge }
        var reader = SSHReader(blob)
        let type = try reader.readUTF8()
        guard type == SSHCertificate.type else { throw SSHCertificateError.unsupportedType(type) }
        let nonce = try reader.readString()
        let publicKey = try reader.readString()
        guard publicKey.count == 32 else { throw SSHCertificateError.invalidKey }
        let serial = try reader.readUInt64()
        let certificateType = try reader.readUInt32()
        let keyID = try reader.readUTF8()
        var principalReader = SSHReader(try reader.readString())
        var principals: [String] = []
        while !principalReader.isAtEnd { principals.append(try principalReader.readUTF8()) }
        let validAfter = try reader.readUInt64()
        let validBefore = try reader.readUInt64()
        let critical = try decodeOptions(try reader.readString())
        let extensions = try decodeOptions(try reader.readString())
        guard try reader.readString().isEmpty else { throw SSHCertificateError.reservedNotEmpty }
        let signatureKey = try reader.readString()
        let signedLength = reader.offset
        let signature = try reader.readString()
        try reader.expectEnd()

        var certificate = SSHCertificate(
            nonce: nonce, publicKey: publicKey, serial: serial, keyID: keyID, principals: principals,
            validAfter: validAfter, validBefore: validBefore, criticalOptions: critical,
            extensions: extensions, signatureKey: signatureKey)
        certificate.certificateType = certificateType
        certificate.signature = signature
        return (certificate, signedLength)
    }

    /// Checks the CA signature over the first `signedLength` bytes of `blob`.
    /// Supports P-256 (this project's CA) and Ed25519 CAs.
    public static func verifySignature(blob: Data) -> Bool {
        guard let (certificate, signedLength) = try? parse(blob), let signature = certificate.signature else { return false }
        let signed = blob.prefix(signedLength)
        switch SSHKeyFormat.keyTypeName(ofBlob: certificate.signatureKey) {
        case SSHKeyFormat.keyType?:
            var reader = SSHReader(certificate.signatureKey)
            guard (try? reader.readUTF8()) != nil, (try? reader.readUTF8()) == SSHKeyFormat.curveName,
                  let point = try? reader.readString(), reader.isAtEnd,
                  let key = try? P256.Signing.PublicKey(x963Representation: point),
                  let raw = try? SSHKeyFormat.rawRS(fromSignatureBlob: signature),
                  let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return key.isValidSignature(ecdsa, for: signed)
        case Ed25519SSH.keyType?:
            guard let raw = try? Ed25519SSH.rawPublicKey(fromBlob: certificate.signatureKey),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw),
                  let sig = try? Ed25519SSH.rawSignature(fromBlob: signature) else { return false }
            return key.isValidSignature(sig, for: signed)
        default:
            return false
        }
    }

    public var forceCommand: String? {
        criticalOptions.first { $0.name == "force-command" }?.stringValue
    }

    public var permitsPTY: Bool { extensions.contains { $0.name == "permit-pty" } }
}

import CryptoKit
import Foundation

public enum SSHKeyFormatError: Error, Equatable {
    case invalidPublicKeyLength
    case invalidSignatureLength
    case unexpectedKeyType(String)
}

/// Encoding of ECDSA P-256 keys and signatures in the OpenSSH formats
/// (RFC 5656 §3.1 and §3.1.2).
public enum SSHKeyFormat {
    public static let keyType = "ecdsa-sha2-nistp256"
    public static let curveName = "nistp256"

    /// `string "ecdsa-sha2-nistp256" || string "nistp256" || string Q`, where Q is
    /// the uncompressed point 0x04 || X || Y (CryptoKit's x963 representation).
    public static func publicKeyBlob(x963 point: Data) throws -> Data {
        guard point.count == 65, point.first == 0x04 else {
            throw SSHKeyFormatError.invalidPublicKeyLength
        }
        var writer = SSHWriter()
        writer.writeString(keyType)
        writer.writeString(curveName)
        writer.writeString(point)
        return writer.data
    }

    public static func publicKeyBlob(_ key: P256.Signing.PublicKey) -> Data {
        // x963Representation is always 65 bytes for P-256.
        try! publicKeyBlob(x963: key.x963Representation)
    }

    /// Returns the key type name stored at the start of any SSH public key blob.
    public static func keyTypeName(ofBlob blob: Data) -> String? {
        var reader = SSHReader(blob)
        return try? reader.readUTF8()
    }

    public static func authorizedKeyLine(blob: Data, comment: String) -> String {
        let type = keyTypeName(ofBlob: blob) ?? keyType
        let line = "\(type) \(blob.base64EncodedString())"
        let cleanComment = comment.filter { !$0.isNewline }
        return cleanComment.isEmpty ? line : "\(line) \(cleanComment)"
    }

    /// OpenSSH SHA256 fingerprint: `SHA256:` + unpadded base64 of SHA-256(blob).
    public static func fingerprint(blob: Data) -> String {
        let digest = Data(SHA256.hash(data: blob))
        let base64 = digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(base64)"
    }

    /// Converts CryptoKit's raw `r || s` (32 + 32 bytes) signature into the SSH
    /// signature blob: `string "ecdsa-sha2-nistp256" || string (mpint r || mpint s)`.
    public static func signatureBlob(rawRS: Data) throws -> Data {
        guard rawRS.count == 64 else { throw SSHKeyFormatError.invalidSignatureLength }
        let raw = Data(rawRS)
        var inner = SSHWriter()
        inner.writeUnsignedMPInt(raw.prefix(32))
        inner.writeUnsignedMPInt(raw.suffix(32))

        var outer = SSHWriter()
        outer.writeString(keyType)
        outer.writeString(inner.data)
        return outer.data
    }

    /// Inverse of `signatureBlob(rawRS:)`, returning the 64-byte `r || s`.
    public static func rawRS(fromSignatureBlob blob: Data) throws -> Data {
        var outer = SSHReader(blob)
        let type = try outer.readUTF8()
        guard type == keyType else { throw SSHKeyFormatError.unexpectedKeyType(type) }
        var inner = SSHReader(try outer.readString())
        try outer.expectEnd()
        let r = try inner.readUnsignedMPInt()
        let s = try inner.readUnsignedMPInt()
        try inner.expectEnd()
        guard r.count <= 32, s.count <= 32 else { throw SSHKeyFormatError.invalidSignatureLength }
        return Data(count: 32 - r.count) + r + Data(count: 32 - s.count) + s
    }

    /// Parses the base64 blob out of an `authorized_keys`/`.pub` style line.
    public static func blob(fromPublicKeyLine line: String) -> Data? {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 2 else { return nil }
        return Data(base64Encoded: String(fields[1]))
    }
}

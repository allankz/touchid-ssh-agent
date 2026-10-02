import Foundation

/// Best-effort description of the data an SSH client asked the agent to sign.
///
/// This is informational only: it is what the requesting local process *claims*
/// it is signing. It is shown in the Touch ID prompt so a person can spot an
/// unexpected request, never used to decide whether to sign.
public enum SignedPayload: Equatable {
    /// SSH_MSG_USERAUTH_REQUEST (RFC 4252 §7). `serverHostKey` is present when the
    /// client used `publickey-hostbound-v00@openssh.com`, which binds the
    /// signature to that host key; the server rejects it under any other key.
    case userAuth(username: String, serverHostKey: Data?)
    /// An `ssh-keygen -Y sign` / git signature (OpenSSH PROTOCOL.sshsig).
    case sshSignature(namespace: String)
    case unknown

    private static let userAuthRequest: UInt8 = 50
    private static let hostBoundMethod = "publickey-hostbound-v00@openssh.com"
    private static let sshsigMagic = Data("SSHSIG".utf8)

    public static func classify(_ data: Data) -> SignedPayload {
        if data.starts(with: sshsigMagic) {
            var reader = SSHReader(data.dropFirst(sshsigMagic.count))
            if let namespace = try? reader.readUTF8() {
                return .sshSignature(namespace: namespace)
            }
            return .unknown
        }
        return (try? parseUserAuth(data)) ?? .unknown
    }

    private static func parseUserAuth(_ data: Data) throws -> SignedPayload {
        var reader = SSHReader(data)
        _ = try reader.readString() // session identifier
        guard try reader.readByte() == userAuthRequest else { return .unknown }
        let username = try reader.readUTF8()
        _ = try reader.readUTF8() // service, normally "ssh-connection"
        let method = try reader.readUTF8()
        guard method == "publickey" || method == hostBoundMethod else { return .unknown }
        guard try reader.readBool() else { return .unknown } // has signature
        _ = try reader.readUTF8() // public key algorithm
        _ = try reader.readString() // public key blob
        var hostKey: Data?
        if method == hostBoundMethod {
            hostKey = try reader.readString()
        }
        try reader.expectEnd()
        return .userAuth(username: username, serverHostKey: hostKey)
    }
}

/// Looks up host names for a server host key in the user's `known_hosts`.
public enum KnownHosts {
    public static var defaultFiles: [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [
            home.appendingPathComponent(".ssh/known_hosts"),
            URL(fileURLWithPath: "/etc/ssh/ssh_known_hosts"),
        ]
    }

    /// Returns the plain-text host names recorded for `hostKey`. Hashed entries
    /// (`HashKnownHosts yes`) cannot be reversed and are skipped.
    public static func names(for hostKey: Data, files: [URL] = defaultFiles) -> [String] {
        var names: [String] = []
        for file in files {
            guard let contents = try? String(contentsOf: file, encoding: .utf8) else { continue }
            for line in contents.split(whereSeparator: \.isNewline) {
                names.append(contentsOf: namesInLine(Substring(line), matching: hostKey))
            }
        }
        var seen = Set<String>()
        return names.filter { seen.insert($0).inserted }
    }

    static func namesInLine(_ line: Substring, matching hostKey: Data) -> [String] {
        let trimmed = line.drop(while: { $0 == " " || $0 == "\t" })
        guard !trimmed.isEmpty, trimmed.first != "#", trimmed.first != "@" else { return [] }
        let fields = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 3, Data(base64Encoded: String(fields[2])) == hostKey else { return [] }
        return fields[0].split(separator: ",").compactMap { pattern in
            guard !pattern.hasPrefix("|"), !pattern.hasPrefix("!") else { return nil }
            return String(pattern)
        }
    }
}

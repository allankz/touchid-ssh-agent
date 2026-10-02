import Foundation

/// Message numbers from the SSH agent protocol (draft-miller-ssh-agent).
public enum AgentMessage {
    public static let failure: UInt8 = 5
    public static let requestIdentities: UInt8 = 11
    public static let identitiesAnswer: UInt8 = 12
    public static let signRequest: UInt8 = 13
    public static let signResponse: UInt8 = 14
    public static let extensionRequest: UInt8 = 27
}

public enum AgentRequest: Equatable {
    case requestIdentities
    case sign(keyBlob: Data, data: Data, flags: UInt32)
    /// Any other message type. The agent answers SSH_AGENT_FAILURE: it never
    /// adds, removes, locks or exports keys, and implements no extensions.
    case unsupported(type: UInt8)
}

public enum AgentProtocol {
    /// Upper bound for a single message. OpenSSH's own agent uses 256 KiB.
    public static let maxMessageLength = 256 * 1024

    /// Parses a message body (the bytes after the uint32 length prefix).
    public static func parseRequest(_ body: Data) throws -> AgentRequest {
        var reader = SSHReader(body)
        let type = try reader.readByte()
        switch type {
        case AgentMessage.requestIdentities:
            try reader.expectEnd()
            return .requestIdentities
        case AgentMessage.signRequest:
            let keyBlob = try reader.readString()
            let data = try reader.readString()
            let flags = try reader.readUInt32()
            try reader.expectEnd()
            return .sign(keyBlob: keyBlob, data: data, flags: flags)
        default:
            return .unsupported(type: type)
        }
    }

    public static func identitiesAnswer(_ identities: [(blob: Data, comment: String)]) -> Data {
        var writer = SSHWriter()
        writer.writeByte(AgentMessage.identitiesAnswer)
        writer.writeUInt32(UInt32(identities.count))
        for identity in identities {
            writer.writeString(identity.blob)
            writer.writeString(identity.comment)
        }
        return writer.data
    }

    public static func signResponse(signatureBlob: Data) -> Data {
        var writer = SSHWriter()
        writer.writeByte(AgentMessage.signResponse)
        writer.writeString(signatureBlob)
        return writer.data
    }

    public static let failure = Data([AgentMessage.failure])

    /// Prepends the uint32 length that frames every agent message.
    public static func frame(_ body: Data) -> Data {
        var writer = SSHWriter()
        writer.writeString(body)
        return writer.data
    }
}

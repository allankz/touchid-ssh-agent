import Foundation

/// Errors raised while decoding SSH wire-format data (RFC 4251 §5).
public enum SSHWireError: Error, Equatable {
    case truncated
    case lengthTooLarge
    case trailingBytes
    case invalidUTF8
    case invalidMPInt
}

/// Bounds-checked reader for SSH wire-format values. Every read validates the
/// remaining length first, so malformed input from the socket can only throw.
public struct SSHReader {
    private let bytes: [UInt8]
    public private(set) var offset = 0

    public init(_ data: Data) {
        bytes = [UInt8](data)
    }

    public var remaining: Int { bytes.count - offset }
    public var isAtEnd: Bool { offset == bytes.count }

    public mutating func readByte() throws -> UInt8 {
        guard remaining >= 1 else { throw SSHWireError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func readBool() throws -> Bool {
        try readByte() != 0
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw SSHWireError.truncated }
        defer { offset += 4 }
        return UInt32(bytes[offset]) << 24
            | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8
            | UInt32(bytes[offset + 3])
    }

    public mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0 else { throw SSHWireError.lengthTooLarge }
        guard remaining >= count else { throw SSHWireError.truncated }
        defer { offset += count }
        return Data(bytes[offset..<offset + count])
    }

    /// Reads a length-prefixed `string` (arbitrary bytes).
    public mutating func readString() throws -> Data {
        let length = try readUInt32()
        guard length <= UInt32(remaining) else { throw SSHWireError.lengthTooLarge }
        return try readBytes(Int(length))
    }

    public mutating func readUTF8() throws -> String {
        guard let text = String(data: try readString(), encoding: .utf8) else {
            throw SSHWireError.invalidUTF8
        }
        return text
    }

    /// Reads a non-negative `mpint` and returns its unsigned big-endian magnitude
    /// without leading zero bytes.
    public mutating func readUnsignedMPInt() throws -> Data {
        let raw = try readString()
        guard let first = raw.first else { return Data() }
        guard first & 0x80 == 0 else { throw SSHWireError.invalidMPInt }
        if first == 0 {
            // A leading zero is only allowed when it is needed for the sign bit.
            guard raw.count > 1, raw[raw.startIndex + 1] & 0x80 != 0 else {
                throw SSHWireError.invalidMPInt
            }
            return Data(raw.dropFirst())
        }
        return raw
    }

    public func expectEnd() throws {
        guard isAtEnd else { throw SSHWireError.trailingBytes }
    }
}

/// Builder for SSH wire-format values.
public struct SSHWriter {
    public private(set) var data = Data()

    public init() {}

    public mutating func writeByte(_ value: UInt8) {
        data.append(value)
    }

    public mutating func writeBool(_ value: Bool) {
        data.append(value ? 1 : 0)
    }

    public mutating func writeUInt32(_ value: UInt32) {
        data.append(contentsOf: [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }

    public mutating func writeString(_ value: Data) {
        writeUInt32(UInt32(value.count))
        data.append(value)
    }

    public mutating func writeString(_ value: String) {
        writeString(Data(value.utf8))
    }

    /// Writes an unsigned big-endian magnitude as a positive `mpint`: leading
    /// zeros are stripped and a 0x00 is prepended when the high bit is set.
    public mutating func writeUnsignedMPInt(_ magnitude: Data) {
        var trimmed = magnitude.drop(while: { $0 == 0 })
        if let first = trimmed.first, first & 0x80 != 0 {
            trimmed = Data([0]) + trimmed
        }
        writeString(Data(trimmed))
    }
}

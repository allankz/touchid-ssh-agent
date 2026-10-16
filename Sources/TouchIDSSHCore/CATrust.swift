import Foundation

/// One option of an authorized_keys line: `name` (lowercased, as sshd matches
/// it case-insensitively) and its unquoted value, if any.
public struct AuthorizedKeysOption: Equatable {
    public let name: String
    public let value: String?

    public init(name: String, value: String? = nil) {
        self.name = name.lowercased()
        self.value = value
    }
}

/// An authorized_keys line split as sshd(8) reads it: options, key type, key
/// blob and comment. Options may hold quoted values with spaces and commas.
public struct AuthorizedKeysLine: Equatable {
    public let options: [AuthorizedKeysOption]
    public let rawOptions: String?
    public let keyType: String
    public let blob: Data

    public var fingerprint: String { SSHKeyFormat.fingerprint(blob: blob) }
    public var isCertAuthority: Bool { options.contains { $0.name == "cert-authority" } }

    public static func parse(_ line: String) -> AuthorizedKeysLine? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        if let plain = keyFields(trimmed) {
            return AuthorizedKeysLine(options: [], rawOptions: nil, keyType: plain.type, blob: plain.blob)
        }
        // Options come first and end at the first unquoted space or tab.
        var inQuotes = false
        var escaped = false
        var end = trimmed.endIndex
        for index in trimmed.indices {
            let character = trimmed[index]
            if escaped { escaped = false; continue }
            if character == "\\" { escaped = true; continue }
            if character == "\"" { inQuotes.toggle(); continue }
            if !inQuotes, character == " " || character == "\t" { end = index; break }
        }
        guard !inQuotes, end < trimmed.endIndex else { return nil }
        let raw = String(trimmed[..<end])
        guard let options = parseOptions(raw),
              let key = keyFields(trimmed[end...].trimmingCharacters(in: .whitespaces)) else { return nil }
        return AuthorizedKeysLine(options: options, rawOptions: raw, keyType: key.type, blob: key.blob)
    }

    /// `type base64 [comment]` when the type matches the type inside the blob.
    static func keyFields(_ text: String) -> (type: String, blob: Data)? {
        let fields = text.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard fields.count >= 2, let blob = Data(base64Encoded: fields[1]),
              SSHKeyFormat.keyTypeName(ofBlob: blob) == fields[0] else { return nil }
        return (fields[0], blob)
    }

    /// Splits `a,b="x,y",c` on commas outside quotes.
    public static func parseOptions(_ raw: String) -> [AuthorizedKeysOption]? {
        var options: [AuthorizedKeysOption] = []
        var name = ""
        var value: String?
        var inQuotes = false
        var escaped = false
        var sawEquals = false
        func finish() -> Bool {
            guard !name.isEmpty else { return false }
            options.append(AuthorizedKeysOption(name: name, value: value))
            name = ""
            value = nil
            sawEquals = false
            return true
        }
        for character in raw {
            if inQuotes {
                if escaped {
                    value?.append(character)
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == "\"" {
                    inQuotes = false
                } else {
                    value?.append(character)
                }
                continue
            }
            switch character {
            case ",":
                guard finish() else { return nil }
            case "=" where !sawEquals:
                sawEquals = true
                value = ""
            case "\"" where sawEquals && value == "":
                inQuotes = true
            default:
                if sawEquals { value?.append(character) } else { name.append(character) }
            }
        }
        guard !inQuotes, finish() else { return nil }
        return options
    }
}

/// How the temporary-access CA is trusted in authorized_keys, and how that
/// trust is checked. The line accepts certificates for exactly one principal
/// and denies forwarding and user rc; PTY stays a per-certificate choice.
public enum CATrust {
    public static let label = "ca"
    public static let restrictions = ["no-agent-forwarding", "no-port-forwarding", "no-X11-forwarding", "no-user-rc"]
    /// Options that only narrow what a certificate can do; an administrator may add them.
    static let narrowingOptions: Set<String> = ["from", "expiry-time", "no-pty", "pty", "command", "restrict", "verify-required"]
    /// Options that re-enable something the CA line denies.
    static let wideningOptions: Set<String> = ["agent-forwarding", "port-forwarding", "x11-forwarding", "user-rc", "permitopen", "permitlisten", "tunnel"]

    public static func options(principal: String) -> String {
        (["cert-authority", "principals=\"\(principal)\""] + restrictions).joined(separator: ",")
    }

    /// The CA as a key to install, with its scope in front.
    public static func authorizedKey(caBlob: Data, comment: String, principal: String) -> AuthorizedKey {
        AuthorizedKey(label: label, type: SSHKeyFormat.keyTypeName(ofBlob: caBlob) ?? SSHKeyFormat.keyType,
                      blob: caBlob, comment: comment, options: options(principal: principal))
    }

    public static func authorizedKey(ca: StoredIdentity, principal: String) -> AuthorizedKey {
        authorizedKey(caBlob: ca.publicKeyBlob, comment: ca.comment, principal: principal)
    }

    /// A stable, opaque principal for one server account.
    public static func principal(targetId: String) -> String { "access-\(targetId)" }

    public static func newTargetId() -> String {
        var generator = SystemRandomNumberGenerator()
        return (0..<8).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &generator)) }.joined()
    }

    public enum Scope: Equatable {
        /// Exactly the options this tool installs.
        case exact
        /// The expected scope plus restrictions an administrator added.
        case narrower
        /// Accepts more than the one principal, or allows something denied.
        case broader(String)
    }

    /// Judges one line holding the CA key against the expected principal.
    public static func scope(of line: AuthorizedKeysLine, principal: String) -> Scope {
        let names = line.options.map(\.name)
        guard names.contains("cert-authority") else {
            return .broader("the key is trusted as a plain login key, not as a CA")
        }
        let principals = line.options.filter { $0.name == "principals" }
        guard principals.count == 1, let value = principals[0].value else {
            return .broader("no principals= option, so any certificate from this CA is accepted")
        }
        let listed = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard listed == [principal] else {
            return .broader("principals=\"\(DisplayText.sanitize(value, maxLength: 80))\" instead of \(principal)")
        }
        let restricted = names.contains("restrict")
        for restriction in restrictions where !restricted && !names.contains(restriction.lowercased()) {
            return .broader("missing \(restriction)")
        }
        if let widening = names.first(where: { wideningOptions.contains($0) }) {
            return .broader("\(widening) re-enables something the CA line denies")
        }
        let known = Set(["cert-authority", "principals"] + restrictions.map { $0.lowercased() }).union(narrowingOptions)
        if let unknown = names.first(where: { !known.contains($0) }) {
            return .broader("unexpected option \(DisplayText.sanitize(unknown, maxLength: 40))")
        }
        let expected = AuthorizedKeysLine.parseOptions(options(principal: principal)) ?? []
        return normalized(line.options) == normalized(expected) ? .exact : .narrower
    }

    /// Judges an options string on its own, as if it preceded the CA key.
    public static func scope(ofOptions raw: String, principal: String) -> Scope? {
        guard let options = AuthorizedKeysLine.parseOptions(raw) else { return nil }
        return scope(of: AuthorizedKeysLine(options: options, rawOptions: raw, keyType: SSHKeyFormat.keyType, blob: Data()),
                     principal: principal)
    }

    /// The recorded options when they still describe the expected scope (as
    /// installed, or narrowed by an administrator) and can be written back in
    /// a single-quoted shell string; otherwise the standard options.
    public static func safeOptions(_ recorded: String, principal: String) -> String {
        guard !recorded.contains("'"), !recorded.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              let scope = scope(ofOptions: recorded, principal: principal) else { return options(principal: principal) }
        if case .broader = scope { return options(principal: principal) }
        return recorded
    }

    static func normalized(_ options: [AuthorizedKeysOption]) -> [String] {
        options.map { "\($0.name)=\($0.value ?? "")" }.sorted()
    }

    /// What authorized_keys says about one CA.
    public struct Report: Equatable {
        /// Scope of every line holding the CA key.
        public var lines: [Scope] = []
        /// Lines holding a CA this entry used to trust (a lost Mac's CA).
        public var retiredLines = 0
        /// `cert-authority` lines for keys this tool does not manage.
        public var otherAuthorities = 0

        public init() {}

        public var isPresent: Bool { !lines.isEmpty }
        /// Present, with no line broader than the expected scope.
        public var isScoped: Bool {
            isPresent && lines.allSatisfy { if case .broader = $0 { return false } else { return true } }
        }

        public var summary: String {
            var parts: [String] = []
            if lines.isEmpty {
                parts.append("CA trust missing")
            } else if let problem = lines.compactMap({ if case .broader(let why) = $0 { return why } else { return nil } }).first {
                parts.append("CA trust broader than expected: \(problem)")
            } else {
                parts.append(lines.contains(.narrower) ? "CA trust scoped (with extra restrictions)" : "CA trust scoped")
                if lines.count > 1 { parts.append("\(lines.count) duplicate CA lines") }
            }
            if retiredLines > 0 { parts.append("a retired CA is still trusted") }
            if otherAuthorities > 0 {
                parts.append("\(otherAuthorities) other cert-authority line\(otherAuthorities == 1 ? "" : "s") not managed by touchid-ssh-agent")
            }
            return parts.joined(separator: "; ")
        }
    }

    /// Inspects the lines of an authorized_keys listing for `caBlob`.
    public static func inspect(_ lines: [String], caBlob: Data, principal: String,
                               retiredFingerprints: Set<String> = []) -> Report {
        var report = Report()
        for text in lines {
            guard let line = AuthorizedKeysLine.parse(text) else { continue }
            if line.blob == caBlob {
                report.lines.append(scope(of: line, principal: principal))
            } else if retiredFingerprints.contains(line.fingerprint) {
                report.retiredLines += 1
            } else if line.isCertAuthority {
                report.otherAuthorities += 1
            }
        }
        return report
    }

    /// The options of the first line holding `caBlob`, as written on the server.
    public static func installedOptions(_ lines: [String], caBlob: Data) -> String? {
        lines.compactMap(AuthorizedKeysLine.parse).first { $0.blob == caBlob }?.rawOptions
    }
}

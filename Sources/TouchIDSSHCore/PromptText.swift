import Foundation

/// Builds the text shown in the Touch ID dialog. macOS renders it as
/// "“touchid-ssh-agent” is trying to <reason>.", so it starts with a verb.
public enum PromptText {
    public static func reason(
        for payload: SignedPayload,
        requester: [ProcessEntry],
        hostNames: (Data) -> [String] = { KnownHosts.names(for: $0) }
    ) -> String {
        let action: String
        switch payload {
        case .userAuth(let username, let hostKey):
            let user = DisplayText.sanitize(username, maxLength: 32)
            if let hostKey {
                action = "log in over SSH as \(user) to \(describeHost(hostKey, names: hostNames(hostKey)))"
            } else {
                action = "log in over SSH as \(user)"
            }
        case .sshSignature(let namespace) where namespace == "git":
            action = "sign a git commit or tag"
        case .sshSignature(let namespace):
            action = "sign data (\(DisplayText.sanitize(namespace, maxLength: 32)))"
        case .unknown:
            action = "sign unidentified SSH data"
        }
        let requesterText = DisplayText.sanitize(PeerInspector.describe(requester), maxLength: 80)
        return "\(action), requested by \(requesterText)"
    }

    static func describeHost(_ hostKey: Data, names: [String]) -> String {
        guard let first = names.first else {
            let fingerprint = SSHKeyFormat.fingerprint(blob: hostKey)
            return "a server not in known_hosts (\(fingerprint.prefix(19))…)"
        }
        let name = DisplayText.sanitize(first, maxLength: 48)
        return names.count > 1 ? "\(name) (+\(names.count - 1))" : name
    }

    /// Payload category for the event log, which never records user or host names.
    public static func logKind(for payload: SignedPayload) -> String {
        switch payload {
        case .userAuth(_, let hostKey): return hostKey == nil ? "login" : "login-hostbound"
        case .sshSignature(let namespace) where namespace == "git": return "git"
        case .sshSignature: return "sshsig"
        case .unknown: return "unknown"
        }
    }
}

/// Minimal append-only event log: time, event, requesting process chain and
/// outcome. It never contains key material, payloads, user names or hosts.
public final class EventLog {
    private let url: URL?
    private let echoToStderr: Bool
    private let lock = NSLock()
    private let maxBytes: UInt64 = 1 << 20
    private let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    public init(url: URL?, echoToStderr: Bool) {
        self.url = url
        self.echoToStderr = echoToStderr
    }

    public func record(_ event: String, _ fields: KeyValuePairs<String, String> = [:]) {
        var line = "\(formatter.string(from: Date())) \(event)"
        for (key, value) in fields {
            line += " \(key)=\(DisplayText.sanitize(value, maxLength: 120).replacingOccurrences(of: " ", with: "_"))"
        }
        line += "\n"

        lock.lock()
        defer { lock.unlock() }
        if echoToStderr {
            FileHandle.standardError.write(Data(line.utf8))
        }
        guard let url else { return }
        rotateIfNeeded(url)
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        _ = line.withCString { write(fd, $0, strlen($0)) }
    }

    private func rotateIfNeeded(_ url: URL) {
        guard let size = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? UInt64,
              size > maxBytes else { return }
        let old = url.appendingPathExtension("1")
        try? FileManager.default.removeItem(at: old)
        try? FileManager.default.moveItem(at: url, to: old)
    }
}

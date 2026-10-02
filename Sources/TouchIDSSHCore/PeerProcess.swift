import Darwin
import Foundation

public struct PeerCredentials {
    public let uid: uid_t
    public let pid: pid_t?
}

public struct ProcessEntry: Equatable {
    public let pid: pid_t
    public let name: String
    public let path: String?

    public init(pid: pid_t, name: String, path: String?) {
        self.pid = pid
        self.name = name
        self.path = path
    }
}

/// Identifies the local process on the other end of the agent socket.
///
/// The pid is used only to describe the requester in the Touch ID prompt and
/// the log. It can be stale (the process may have exited and the pid reused),
/// so it is never used for an authorization decision; the uid check is.
public enum PeerInspector {
    public static func credentials(of socket: Int32) -> PeerCredentials? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(socket, &uid, &gid) == 0 else { return nil }

        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        let hasPid = getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0
        return PeerCredentials(uid: uid, pid: hasPid ? pid : nil)
    }

    /// Walks from `pid` up through its parents, stopping at launchd, at the first
    /// GUI application, or after `maxDepth` entries.
    public static func processChain(from pid: pid_t, maxDepth: Int = 5) -> [ProcessEntry] {
        var chain: [ProcessEntry] = []
        var current = pid
        while current > 1, chain.count < maxDepth {
            guard let entry = entry(for: current) else { break }
            chain.append(entry)
            if let path = entry.path, path.contains(".app/Contents/MacOS/") { break }
            guard let parent = parentPID(of: current), parent != current else { break }
            current = parent
        }
        return chain
    }

    /// Human-readable chain such as `ssh ← zsh ← Terminal`.
    public static func describe(_ chain: [ProcessEntry]) -> String {
        guard !chain.isEmpty else { return "unknown process" }
        return chain.map(\.name).joined(separator: " ← ")
    }

    static func entry(for pid: pid_t) -> ProcessEntry? {
        var pathBuffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        let path = pathLength > 0 ? String(cString: pathBuffer) : nil

        var nameBuffer = [CChar](repeating: 0, count: 256)
        let nameLength = proc_name(pid, &nameBuffer, UInt32(nameBuffer.count))
        var name = nameLength > 0 ? String(cString: nameBuffer) : ""

        if let path, let range = path.range(of: ".app/Contents/MacOS/") {
            // Prefer the bundle name for GUI apps ("Terminal", "Claude").
            name = URL(fileURLWithPath: String(path[..<range.lowerBound])).lastPathComponent
        } else if name.isEmpty, let path {
            name = URL(fileURLWithPath: path).lastPathComponent
        }
        guard !name.isEmpty else { return nil }
        return ProcessEntry(pid: pid, name: DisplayText.sanitize(name, maxLength: 40), path: path)
    }

    static func parentPID(of pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return pid_t(info.pbi_ppid)
    }
}

/// Makes untrusted strings safe to show in a system prompt or a log line.
public enum DisplayText {
    public static func sanitize(_ text: String, maxLength: Int) -> String {
        let cleaned = String(text.unicodeScalars.filter { scalar in
            !CharacterSet.controlCharacters.contains(scalar)
                && !CharacterSet.illegalCharacters.contains(scalar)
        }.map(Character.init))
        guard cleaned.count > maxLength else { return cleaned }
        return String(cleaned.prefix(maxLength - 1)) + "…"
    }
}

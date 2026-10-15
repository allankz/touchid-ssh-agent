import Darwin
import Foundation

/// One connection on a grant's control socket: newline-delimited JSON objects,
/// each at most 64 KiB. The CLI uses it to follow issuance (attach, issued,
/// confirm), to ask for status and to stop the grant.
public final class ControlConnection {
    static let maxMessage = 64 * 1024
    let fd: Int32
    private var buffer = Data()
    private var closed = false
    private let lock = NSLock()

    init(fd: Int32) {
        self.fd = fd
        var enabled: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
    }

    deinit { close() }

    /// Connects to a control socket, retrying until `timeout` while the job starts.
    public static func connect(_ path: String, timeout: TimeInterval = 0) -> ControlConnection? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if let fd = AgentClient.connect(socketPath: path) { return ControlConnection(fd: fd) }
            if Date() >= deadline { break }
            usleep(50_000)
        } while true
        return nil
    }

    @discardableResult
    public func send(_ message: [String: Any]) -> Bool {
        guard let data = try? JSONSerialization.data(withJSONObject: message, options: [.sortedKeys]),
              data.count < ControlConnection.maxMessage else { return false }
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return false }
        return SocketIO.writeAll(fd, data + Data("\n".utf8))
    }

    /// The next message, or nil at end of stream, on a malformed message or
    /// after `timeout` seconds.
    public func receive(timeout: TimeInterval? = nil) -> [String: Any]? {
        let deadline = timeout.map { Date().addingTimeInterval($0) }
        while true {
            if let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[(newline + 1)...])
                return (try? JSONSerialization.jsonObject(with: line)) as? [String: Any]
            }
            guard buffer.count < ControlConnection.maxMessage else { return nil }
            var waitMilliseconds: Int32 = -1
            if let deadline {
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0 else { return nil }
                waitMilliseconds = Int32(min(remaining * 1000, Double(Int32.max)))
            }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, waitMilliseconds)
            if ready < 0, errno == EINTR { continue }
            guard ready > 0 else { return nil }
            var chunk = [UInt8](repeating: 0, count: 4096)
            let count = read(fd, &chunk, chunk.count)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return nil }
            buffer.append(contentsOf: chunk[0..<count])
        }
    }

    /// Sends `message` and waits for the reply.
    public func request(_ message: [String: Any], timeout: TimeInterval) -> [String: Any]? {
        guard send(message) else { return nil }
        return receive(timeout: timeout)
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)
    }

    /// Unblocks a pending `receive` on another thread without closing the descriptor.
    public func interrupt() {
        shutdown(fd, SHUT_RDWR)
    }
}

/// One-shot control requests used by `access status` and `access stop`.
public enum AccessControl {
    public static func request(_ directory: GrantDirectory, _ message: [String: Any], timeout: TimeInterval = 3) -> [String: Any]? {
        guard let connection = ControlConnection.connect(directory.controlSocket.path) else { return nil }
        defer { connection.close() }
        return connection.request(message, timeout: timeout)
    }
}

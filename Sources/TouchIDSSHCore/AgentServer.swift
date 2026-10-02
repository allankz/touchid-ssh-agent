import Darwin
import Foundation

public enum AgentServerError: Error, CustomStringConvertible {
    case socketPathTooLong(String)
    case alreadyRunning(String)
    case notASocket(String)
    case system(String, Int32)

    public var description: String {
        switch self {
        case .socketPathTooLong(let path):
            return "Socket path is too long for a Unix socket: \(path)"
        case .alreadyRunning(let path):
            return "Another agent is already serving \(path)."
        case .notASocket(let path):
            return "\(path) exists and is not a socket; refusing to remove it."
        case .system(let call, let code):
            return "\(call) failed: \(String(cString: strerror(code)))"
        }
    }
}

/// SSH agent listening on a Unix socket. It answers only "list identities" and
/// "sign"; every signature goes through Touch ID via `SecureEnclaveSigner`.
public final class AgentServer {
    public typealias Signer = (_ data: Data, _ identity: StoredIdentity, _ reason: String) throws -> Data

    private let paths: AgentPaths
    private let log: EventLog
    private let signer: Signer
    private let maxConnections = 64

    private var listenSocket: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private let acceptQueue = DispatchQueue(label: "touchid-ssh-agent.accept")
    private let connectionSlots: DispatchSemaphore
    /// One Touch ID prompt at a time; concurrent sign requests wait their turn.
    private let signLock = NSLock()

    public init(
        paths: AgentPaths,
        log: EventLog,
        signer: @escaping Signer = { data, identity, reason in
            try SecureEnclaveSigner.sign(data, with: identity, reason: reason)
        }
    ) {
        self.paths = paths
        self.log = log
        self.signer = signer
        connectionSlots = DispatchSemaphore(value: maxConnections)
    }

    deinit { stop() }

    public func start() throws {
        signal(SIGPIPE, SIG_IGN)
        try paths.ensureDirectory()
        let path = paths.socket.path
        try removeStaleSocket(at: path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AgentServerError.system("socket", errno) }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            close(fd)
            throw AgentServerError.socketPathTooLong(path)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
            buffer[pathBytes.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        // The socket is created 0600 (umask) inside a 0700 directory.
        let previousMask = umask(0o177)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previousMask)
        guard bound == 0 else {
            let code = errno
            close(fd)
            throw AgentServerError.system("bind", code)
        }
        chmod(path, 0o600)
        guard listen(fd, 16) == 0 else {
            let code = errno
            close(fd)
            throw AgentServerError.system("listen", code)
        }

        listenSocket = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: acceptQueue)
        source.setEventHandler { [weak self] in self?.acceptConnection() }
        source.setCancelHandler { close(fd) }
        acceptSource = source
        source.resume()
        log.record("listening", ["socket": paths.displayPath(paths.socket)])
    }

    /// Stops accepting connections and removes the socket file.
    public func stop() {
        guard let source = acceptSource else { return }
        acceptSource = nil
        source.cancel()
        unlink(paths.socket.path)
        listenSocket = -1
    }

    private func removeStaleSocket(at path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0 else { return }
        guard info.st_mode & S_IFMT == S_IFSOCK else { throw AgentServerError.notASocket(path) }
        if AgentClient.isListening(socketPath: path) {
            throw AgentServerError.alreadyRunning(path)
        }
        unlink(path)
    }

    private func acceptConnection() {
        let client = accept(listenSocket, nil, nil)
        guard client >= 0 else { return }
        guard connectionSlots.wait(timeout: .now()) == .success else {
            log.record("rejected", ["reason": "too-many-connections"])
            close(client)
            return
        }
        let thread = Thread { [self] in
            defer { connectionSlots.signal() }
            serve(client)
        }
        thread.name = "touchid-ssh-agent.connection"
        thread.start()
    }

    private func serve(_ client: Int32) {
        defer { close(client) }
        var enabled: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))

        guard let peer = PeerInspector.credentials(of: client), peer.uid == getuid() else {
            log.record("rejected", ["reason": "foreign-uid"])
            return
        }

        while let body = SocketIO.readMessage(client) {
            guard let response = handle(body, peer: peer) else { return }
            guard SocketIO.writeAll(client, AgentProtocol.frame(response)) else { return }
        }
    }

    /// Returns the response body, or nil to drop a connection that sent garbage.
    func handle(_ body: Data, peer: PeerCredentials) -> Data? {
        let request: AgentRequest
        do {
            request = try AgentProtocol.parseRequest(body)
        } catch {
            log.record("malformed", ["requester": requester(peer)])
            return nil
        }

        switch request {
        case .requestIdentities:
            guard let identity = loadIdentity() else { return AgentProtocol.identitiesAnswer([]) }
            return AgentProtocol.identitiesAnswer([(identity.publicKeyBlob, identity.comment)])

        case .sign(let keyBlob, let data, _):
            guard let identity = loadIdentity(), identity.publicKeyBlob == keyBlob else {
                return AgentProtocol.failure
            }
            return sign(data, with: identity, peer: peer)

        case .unsupported:
            return AgentProtocol.failure
        }
    }

    private func sign(_ data: Data, with identity: StoredIdentity, peer: PeerCredentials) -> Data {
        signLock.lock()
        defer { signLock.unlock() }

        let chain = peer.pid.map { PeerInspector.processChain(from: $0) } ?? []
        let payload = SignedPayload.classify(data)
        let reason = PromptText.reason(for: payload, requester: chain)
        let kind = PromptText.logKind(for: payload)
        let requesterText = PeerInspector.describe(chain)

        do {
            let signature = try signer(data, identity, reason)
            log.record("approved", ["kind": kind, "requester": requesterText])
            return AgentProtocol.signResponse(signatureBlob: signature)
        } catch let error as SignError {
            log.record("denied", ["kind": kind, "requester": requesterText, "why": error.logCode])
            if error == .biometryLockout || error == .biometryUnavailable || error == .biometryNotEnrolled {
                log.record("hint", ["message": error.description])
            }
            return AgentProtocol.failure
        } catch {
            log.record("denied", ["kind": kind, "requester": requesterText, "why": "error"])
            return AgentProtocol.failure
        }
    }

    private func requester(_ peer: PeerCredentials) -> String {
        PeerInspector.describe(peer.pid.map { PeerInspector.processChain(from: $0) } ?? [])
    }

    private func loadIdentity() -> StoredIdentity? {
        do {
            return try IdentityStore.load(from: paths)
        } catch {
            log.record("identity-error", ["error": "\(error)"])
            return nil
        }
    }
}

/// Blocking framed I/O on a connected socket.
enum SocketIO {
    static func readMessage(_ fd: Int32) -> Data? {
        guard let header = readExactly(fd, count: 4) else { return nil }
        let length = header.reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, length <= AgentProtocol.maxMessageLength else { return nil }
        return readExactly(fd, count: length)
    }

    static func readExactly(_ fd: Int32, count: Int) -> Data? {
        var buffer = [UInt8](repeating: 0, count: count)
        var received = 0
        while received < count {
            let n = buffer.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress! + received, count - received)
            }
            if n > 0 {
                received += n
            } else if n < 0, errno == EINTR {
                continue
            } else {
                return nil
            }
        }
        return Data(buffer)
    }

    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        let bytes = [UInt8](data)
        var sent = 0
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { raw in
                write(fd, raw.baseAddress! + sent, bytes.count - sent)
            }
            if n > 0 {
                sent += n
            } else if n < 0, errno == EINTR {
                continue
            } else {
                return false
            }
        }
        return true
    }
}

/// Small agent client used for status checks and tests.
public enum AgentClient {
    public static func connect(socketPath: String) -> Int32? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            close(fd)
            return nil
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
            buffer[pathBytes.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            close(fd)
            return nil
        }
        var enabled: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }

    public static func isListening(socketPath: String) -> Bool {
        guard let fd = connect(socketPath: socketPath) else { return false }
        close(fd)
        return true
    }

    /// Sends one request body and returns the response body.
    public static func roundTrip(socketPath: String, body: Data) -> Data? {
        guard let fd = connect(socketPath: socketPath) else { return nil }
        defer { close(fd) }
        guard SocketIO.writeAll(fd, AgentProtocol.frame(body)) else { return nil }
        return SocketIO.readMessage(fd)
    }

    /// Public key blobs and comments the agent at `socketPath` offers.
    public static func listIdentities(socketPath: String) -> [(blob: Data, comment: String)]? {
        guard let response = roundTrip(socketPath: socketPath, body: Data([AgentMessage.requestIdentities])) else {
            return nil
        }
        var reader = SSHReader(response)
        guard (try? reader.readByte()) == AgentMessage.identitiesAnswer,
              let count = try? reader.readUInt32() else { return nil }
        var identities: [(Data, String)] = []
        for _ in 0..<count {
            guard let blob = try? reader.readString(), let comment = try? reader.readUTF8() else { return nil }
            identities.append((blob, comment))
        }
        return identities
    }
}

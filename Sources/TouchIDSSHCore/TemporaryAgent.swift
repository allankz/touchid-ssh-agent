import CryptoKit
import Darwin
import Foundation

/// Time sources for a grant deadline, injectable so tests can move the clocks
/// without touching the system time.
public protocol GrantClock {
    /// Seconds since 1970. Jumps when someone changes the system clock.
    var wallSeconds: TimeInterval { get }
    /// Seconds on a clock that never goes backwards and keeps counting while
    /// the Mac sleeps (`CLOCK_MONOTONIC` on Darwin).
    var monotonicSeconds: TimeInterval { get }
}

public struct SystemGrantClock: GrantClock {
    public init() {}
    public var wallSeconds: TimeInterval { Date().timeIntervalSince1970 }
    public var monotonicSeconds: TimeInterval { TimeInterval(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000 }
}

/// A deadline enforced on both clocks: setting the wall clock back cannot
/// extend it, and neither can sleep or a late timer.
public struct GrantDeadline {
    public let expiresAt: TimeInterval
    let monotonicDeadline: TimeInterval
    let clock: GrantClock

    public init(expiresAt: TimeInterval, clock: GrantClock = SystemGrantClock()) {
        self.expiresAt = expiresAt
        self.clock = clock
        monotonicDeadline = clock.monotonicSeconds + (expiresAt - clock.wallSeconds)
    }

    public var isExpired: Bool {
        clock.wallSeconds >= expiresAt || clock.monotonicSeconds >= monotonicDeadline
    }

    public var remaining: TimeInterval {
        max(0, min(expiresAt - clock.wallSeconds, monotonicDeadline - clock.monotonicSeconds))
    }
}

/// The agent behind a temporary grant (and behind the short validation checks
/// of `authorize` and `recover`). It holds one Ed25519 key in memory and its
/// certificate, and signs SSH logins with it without Touch ID until the
/// deadline. It never holds or offers the CA.
public final class TemporaryAgent {
    public let socketPath: String
    public let credential: IssuedCertificate
    public let deadline: GrantDeadline
    /// Remote accounts the certificate is for; other login requests are refused.
    public let allowedUsers: Set<String>
    private let comment: String
    private let log: EventLog?
    private let logName: String
    private let maxConnections = 32

    private let lock = NSLock()
    private var listenSocket: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private let acceptQueue = DispatchQueue(label: "touchid-ssh-agent.temporary.accept")
    private var clients = Set<Int32>()
    private var stopped = false
    private var signatures = 0

    public init(socketPath: String, credential: IssuedCertificate, deadline: GrantDeadline,
                allowedUsers: Set<String>, comment: String, log: EventLog?, logName: String) {
        self.socketPath = socketPath
        self.credential = credential
        self.deadline = deadline
        self.allowedUsers = allowedUsers
        self.comment = RemoteKeys.safeComment(comment)
        self.log = log
        self.logName = logName
    }

    deinit { stop() }

    public var certificateBlob: Data { credential.blob }
    public var keyBlob: Data { credential.publicKeyBlob }
    public var signatureCount: Int { lock.lock(); defer { lock.unlock() }; return signatures }

    public func start() throws {
        signal(SIGPIPE, SIG_IGN)
        var info = stat()
        if lstat(socketPath, &info) == 0 { throw AgentServerError.notASocket(socketPath) }
        let fd = try UnixSocket.listen(at: socketPath)
        lock.lock()
        listenSocket = fd
        lock.unlock()
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: acceptQueue)
        source.setEventHandler { [weak self] in self?.acceptConnection() }
        source.setCancelHandler { close(fd) }
        acceptSource = source
        source.resume()
    }

    /// Stops accepting, closes every connected client and removes the socket.
    /// Authenticated SSH sessions are not affected: they no longer need the agent.
    public func stop() {
        lock.lock()
        let wasStopped = stopped
        stopped = true
        for client in clients { shutdown(client, SHUT_RDWR) }
        let source = acceptSource
        acceptSource = nil
        lock.unlock()
        // Only a socket this agent bound is removed.
        guard !wasStopped, let source else { return }
        source.cancel()
        unlink(socketPath)
    }

    private func acceptConnection() {
        let client = accept(listenSocket, nil, nil)
        guard client >= 0 else { return }
        lock.lock()
        guard !stopped, clients.count < maxConnections else {
            lock.unlock()
            close(client)
            return
        }
        clients.insert(client)
        lock.unlock()
        let thread = Thread { [self] in
            serve(client)
            lock.lock()
            clients.remove(client)
            lock.unlock()
            close(client)
        }
        thread.name = "touchid-ssh-agent.temporary.connection"
        thread.start()
    }

    private func serve(_ client: Int32) {
        var enabled: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        guard let peer = PeerInspector.credentials(of: client), peer.uid == getuid() else {
            log?.record("rejected", ["grant": logName, "reason": "foreign-uid"])
            return
        }
        while let body = SocketIO.readMessage(client) {
            guard let response = handle(body, peer: peer) else { return }
            guard SocketIO.writeAll(client, AgentProtocol.frame(response)) else { return }
        }
    }

    /// Returns the response body, or nil to drop a connection that sent garbage.
    func handle(_ body: Data, peer: PeerCredentials) -> Data? {
        guard let request = try? AgentProtocol.parseRequest(body) else {
            log?.record("malformed", ["grant": logName])
            return nil
        }
        switch request {
        case .requestIdentities:
            guard !deadline.isExpired else { return AgentProtocol.identitiesAnswer([]) }
            return AgentProtocol.identitiesAnswer([(certificateBlob, comment), (keyBlob, comment)])
        case .sign(let blob, let data, _):
            guard blob == certificateBlob || blob == keyBlob else { return AgentProtocol.failure }
            return sign(data, peer: peer)
        case .unsupported:
            return AgentProtocol.failure
        }
    }

    private func sign(_ data: Data, peer: PeerCredentials) -> Data {
        let requester = PeerInspector.describe(peer.pid.map { PeerInspector.processChain(from: $0) } ?? [])
        // Checked on every request, including clients connected before expiry.
        guard !deadline.isExpired else {
            log?.record("refused", ["grant": logName, "why": "expired", "requester": requester])
            return AgentProtocol.failure
        }
        guard let user = TemporaryAgent.loginUser(in: data, offering: [certificateBlob, keyBlob]),
              allowedUsers.contains(user) else {
            log?.record("refused", ["grant": logName, "why": "not-a-login", "requester": requester])
            return AgentProtocol.failure
        }
        guard let signature = try? credential.privateKey.signature(for: data) else { return AgentProtocol.failure }
        lock.lock()
        signatures += 1
        lock.unlock()
        log?.record("signed", ["grant": logName, "serial": String(credential.certificate.serial), "requester": requester])
        return AgentProtocol.signResponse(signatureBlob: Ed25519SSH.signatureBlob(signature))
    }

    /// The account of an SSH_MSG_USERAUTH_REQUEST that offers one of `blobs`;
    /// nil for anything else (git signatures, arbitrary data).
    static func loginUser(in data: Data, offering blobs: [Data]) -> String? {
        var reader = SSHReader(data)
        guard (try? reader.readString()) != nil, (try? reader.readByte()) == 50,
              let user = try? reader.readUTF8(), (try? reader.readUTF8()) != nil,
              let method = try? reader.readUTF8(),
              method == "publickey" || method == "publickey-hostbound-v00@openssh.com",
              (try? reader.readBool()) == true, (try? reader.readUTF8()) != nil,
              let offered = try? reader.readString(), blobs.contains(offered) else { return nil }
        if method != "publickey" { guard (try? reader.readString()) != nil else { return nil } }
        guard reader.isAtEnd else { return nil }
        return user
    }
}

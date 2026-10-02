// Self-test suite. Run with `swift run touchid-ssh-agent-selftest [--docker]`.
//
// XCTest is not available with Command Line Tools only, so this is a plain
// executable. OpenSSH (`ssh-keygen`, `ssh-add`, `ssh`) serves as the oracle for
// key, signature and protocol compatibility. The keys created here use a
// test-only Secure Enclave policy without Touch ID, so nothing prompts.

import CryptoKit
import Darwin
import Foundation
@_spi(Testing) import TouchIDSSHCore

// MARK: - Harness

var passed = 0
var failed: [String] = []
var currentTest = ""

func check(_ condition: @autoclosure () throws -> Bool, _ message: String, line: Int = #line) {
    if (try? condition()) != true {
        failed.append("\(currentTest): \(message) (line \(line))")
        print("    ✗ \(message) (line \(line))")
    }
}

func test(_ name: String, _ body: () throws -> Void) {
    currentTest = name
    let failuresBefore = failed.count
    do {
        try body()
    } catch {
        failed.append("\(name): unexpected error \(error)")
        print("    ✗ unexpected error: \(error)")
    }
    if failed.count == failuresBefore {
        passed += 1
        print("  ✓ \(name)")
    } else {
        print("  ✗ \(name)")
    }
}

func throwsError(_ body: () throws -> Void) -> Bool {
    do { try body() } catch { return true }
    return false
}

struct CommandResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

@discardableResult
func run(_ executable: String, _ arguments: [String], environment: [String: String] = [:], stdin: Data? = nil) throws -> CommandResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.environment = ProcessInfo.processInfo.environment.merging(environment) { $1 }
    let out = Pipe(), err = Pipe(), input = Pipe()
    process.standardOutput = out
    process.standardError = err
    process.standardInput = input
    try process.run()
    if let stdin { input.fileHandleForWriting.write(stdin) }
    try input.fileHandleForWriting.close()
    let stdoutData = out.fileHandleForReading.readDataToEndOfFile()
    let stderrData = err.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CommandResult(
        status: process.terminationStatus,
        stdout: String(decoding: stdoutData, as: UTF8.self),
        stderr: String(decoding: stderrData, as: UTF8.self)
    )
}

func hex(_ string: String) -> Data {
    var data = Data()
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        data.append(UInt8(string[index..<next], radix: 16)!)
        index = next
    }
    return data
}

/// Short temp directory: Unix socket paths are limited to 104 bytes on macOS.
func makeTempDirectory() throws -> URL {
    var template = Array((NSTemporaryDirectory() + "tidssh-XXXXXX").utf8CString)
    guard let path = mkdtemp(&template) else { throw CocoaError(.fileWriteUnknown) }
    return URL(fileURLWithPath: String(cString: path))
}

func userAuthData(username: String, keyBlob: Data, hostKey: Data?) -> Data {
    var writer = SSHWriter()
    writer.writeString(Data(repeating: 0xAB, count: 32))
    writer.writeByte(50)
    writer.writeString(username)
    writer.writeString("ssh-connection")
    writer.writeString(hostKey == nil ? "publickey" : "publickey-hostbound-v00@openssh.com")
    writer.writeBool(true)
    writer.writeString(SSHKeyFormat.keyType)
    writer.writeString(keyBlob)
    if let hostKey { writer.writeString(hostKey) }
    return writer.data
}

let runDocker = CommandLine.arguments.contains("--docker")

// MARK: - Wire format

print("SSH wire format")

test("mpint: zero, high bit and leading zeros") {
    func encode(_ bytes: [UInt8]) -> Data {
        var writer = SSHWriter()
        writer.writeUnsignedMPInt(Data(bytes))
        return writer.data
    }
    check(encode([]) == hex("00000000"), "empty zero")
    check(encode([0x00, 0x00]) == hex("00000000"), "padded zero")
    check(encode([0x7F]) == hex("000000017f"), "0x7f")
    check(encode([0x80]) == hex("000000020080"), "0x80 gets a 0x00 prefix")
    check(encode([0x00, 0x00, 0x01, 0x02]) == hex("000000020102"), "leading zeros stripped")
}

test("mpint: decoding rejects negative and non-minimal values") {
    var negative = SSHReader(hex("0000000180"))
    check(throwsError { _ = try negative.readUnsignedMPInt() }, "negative")
    var padded = SSHReader(hex("000000020001"))
    check(throwsError { _ = try padded.readUnsignedMPInt() }, "unnecessary zero")
    var good = SSHReader(hex("000000020080"))
    check((try? good.readUnsignedMPInt()) == Data([0x80]), "valid 0x80")
}

test("reader rejects truncated data") {
    var shortInt = SSHReader(Data([0, 0, 1]))
    check(throwsError { _ = try shortInt.readUInt32() }, "uint32 with 3 bytes")
    var longString = SSHReader(hex("00000010abcd"))
    check(throwsError { _ = try longString.readString() }, "string longer than the buffer")
    var huge = SSHReader(hex("ffffffff"))
    check(throwsError { _ = try huge.readString() }, "4 GiB length")
}

test("signature: r||s round trip with high bits and zeros") {
    for _ in 0..<200 {
        var raw = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        if Bool.random() { raw[0] = 0 }
        if Bool.random() { raw[32] = 0x80 }
        let blob = try SSHKeyFormat.signatureBlob(rawRS: raw)
        check(try SSHKeyFormat.rawRS(fromSignatureBlob: blob) == raw, "round trip")
    }
    check(throwsError { _ = try SSHKeyFormat.signatureBlob(rawRS: Data(count: 63)) }, "wrong length")
}

test("encoded CryptoKit signature verifies after decoding") {
    let key = P256.Signing.PrivateKey()
    let message = Data("message".utf8)
    let blob = try SSHKeyFormat.signatureBlob(rawRS: try key.signature(for: message).rawRepresentation)
    let decoded = try P256.Signing.ECDSASignature(rawRepresentation: try SSHKeyFormat.rawRS(fromSignatureBlob: blob))
    check(key.publicKey.isValidSignature(decoded, for: message), "verifies")
}

test("public key and fingerprint match ssh-keygen") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    for _ in 0..<5 {
        let key = P256.Signing.PrivateKey().publicKey
        let blob = SSHKeyFormat.publicKeyBlob(key)
        let file = directory.appendingPathComponent("k.pub")
        try (SSHKeyFormat.authorizedKeyLine(blob: blob, comment: "test") + "\n").write(to: file, atomically: true, encoding: .utf8)
        let result = try run("/usr/bin/ssh-keygen", ["-lf", file.path])
        check(result.status == 0, "ssh-keygen accepted the key: \(result.stderr)")
        check(result.stdout.contains(SSHKeyFormat.fingerprint(blob: blob)), "same fingerprint: \(result.stdout)")
        check(result.stdout.contains("(ECDSA)"), "ECDSA type")
    }
}

// MARK: - Agent protocol

print("Agent protocol")

test("parses valid and invalid requests") {
    check(try AgentProtocol.parseRequest(Data([11])) == .requestIdentities, "list")
    check(throwsError { _ = try AgentProtocol.parseRequest(Data([11, 0])) }, "list with trailing bytes")
    check(throwsError { _ = try AgentProtocol.parseRequest(Data()) }, "empty")

    var sign = SSHWriter()
    sign.writeByte(13)
    sign.writeString(Data([1, 2, 3]))
    sign.writeString(Data([4, 5]))
    sign.writeUInt32(2)
    check(try AgentProtocol.parseRequest(sign.data) == .sign(keyBlob: Data([1, 2, 3]), data: Data([4, 5]), flags: 2), "sign")
    check(throwsError { _ = try AgentProtocol.parseRequest(sign.data + Data([0])) }, "sign with trailing bytes")
    check(throwsError { _ = try AgentProtocol.parseRequest(sign.data.dropLast()) }, "truncated sign")

    check(try AgentProtocol.parseRequest(Data([27, 0, 0, 0, 0])) == .unsupported(type: 27), "extension")
    check(try AgentProtocol.parseRequest(Data([17])) == .unsupported(type: 17), "add key")
}

test("fuzz: random bytes never crash the parser") {
    for _ in 0..<20_000 {
        let body = Data((0..<Int.random(in: 0...64)).map { _ in UInt8.random(in: 0...255) })
        _ = try? AgentProtocol.parseRequest(body)
        _ = SignedPayload.classify(body)
        _ = try? SSHKeyFormat.rawRS(fromSignatureBlob: body)
    }
}

test("classifies login, hostbound login, git and unknown") {
    let blob = SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey)
    let hostKey = SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey)
    check(SignedPayload.classify(userAuthData(username: "admin", keyBlob: blob, hostKey: nil))
        == .userAuth(username: "admin", serverHostKey: nil), "login")
    check(SignedPayload.classify(userAuthData(username: "deploy", keyBlob: blob, hostKey: hostKey))
        == .userAuth(username: "deploy", serverHostKey: hostKey), "hostbound")

    var sshsig = SSHWriter()
    sshsig.writeString("git")
    sshsig.writeString("")
    sshsig.writeString("sha512")
    sshsig.writeString(Data(count: 64))
    check(SignedPayload.classify(Data("SSHSIG".utf8) + sshsig.data) == .sshSignature(namespace: "git"), "git")
    check(SignedPayload.classify(Data("arbitrary junk".utf8)) == .unknown, "unknown")
    check(SignedPayload.classify(userAuthData(username: "a", keyBlob: blob, hostKey: nil) + Data([0])) == .unknown, "trailing bytes")
}

test("known_hosts: plain names, skips hashes, markers and comments") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let hostKey = SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey)
    let other = SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey)
    let file = directory.appendingPathComponent("known_hosts")
    try """
    # comment
    server.example,[10.0.0.5]:2222 \(SSHKeyFormat.keyType) \(hostKey.base64EncodedString())
    |1|c2FsdA==|aGFzaA== \(SSHKeyFormat.keyType) \(hostKey.base64EncodedString())
    @revoked revoked.example \(SSHKeyFormat.keyType) \(hostKey.base64EncodedString())
    other.example \(SSHKeyFormat.keyType) \(other.base64EncodedString())
    """.write(to: file, atomically: true, encoding: .utf8)
    check(KnownHosts.names(for: hostKey, files: [file]) == ["server.example", "[10.0.0.5]:2222"], "names")
    check(KnownHosts.names(for: Data([1, 2]), files: [file]).isEmpty, "missing key")
}

test("Touch ID text describes the request and requester") {
    let hostKey = Data([9, 9, 9])
    let chain = [
        ProcessEntry(pid: 10, name: "ssh", path: "/usr/bin/ssh"),
        ProcessEntry(pid: 9, name: "zsh", path: "/bin/zsh"),
        ProcessEntry(pid: 8, name: "Terminal", path: nil),
    ]
    let known = PromptText.reason(for: .userAuth(username: "admin", serverHostKey: hostKey), requester: chain) { _ in ["server.example"] }
    check(known == "log in over SSH as admin to server.example, requested by ssh ← zsh ← Terminal", known)
    let unknown = PromptText.reason(for: .userAuth(username: "admin", serverHostKey: hostKey), requester: []) { _ in [] }
    check(unknown.contains("not in known_hosts (SHA256:"), unknown)
    check(unknown.hasSuffix("requested by unknown process"), unknown)
    check(PromptText.reason(for: .userAuth(username: "root", serverHostKey: nil), requester: chain) { _ in [] }
        .hasPrefix("log in over SSH as root, requested by"), "no host")
    check(PromptText.reason(for: .sshSignature(namespace: "git"), requester: chain).hasPrefix("sign a git commit"), "git")
    let hostile = PromptText.reason(for: .userAuth(username: "x\n\u{1b}[2Jroot", serverHostKey: nil), requester: chain) { _ in [] }
    check(!hostile.contains("\n") && !hostile.contains("\u{1b}"), "strips control characters: \(hostile)")
}

test("LaunchAgent: restarts only after failures and passes a custom directory") {
    let custom = AgentPaths(directory: URL(fileURLWithPath: "/tmp/tidssh-plist"))
    let data = try LaunchAgent.plist(executable: "/opt/bin/touchid-ssh-agent", paths: custom)
    let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
    check(plist?["Label"] as? String == "local.touchid-ssh-agent", "label")
    check(plist?["ProgramArguments"] as? [String] == ["/opt/bin/touchid-ssh-agent", "agent"], "arguments")
    check((plist?["KeepAlive"] as? [String: Bool])?["SuccessfulExit"] == false, "KeepAlive only on failure")
    check((plist?["EnvironmentVariables"] as? [String: String])?[AgentPaths.environmentVariable] == "/tmp/tidssh-plist", "directory")
    let standard = try LaunchAgent.plist(executable: "/x", paths: AgentPaths(directory: AgentPaths.defaultDirectory))
    let standardPlist = try PropertyListSerialization.propertyList(from: standard, format: nil) as? [String: Any]
    check(standardPlist?["EnvironmentVariables"] == nil, "no environment for the default directory")
}

test("process chain of the test itself") {
    let chain = PeerInspector.processChain(from: getpid())
    check(chain.first?.pid == getpid(), "starts at this process")
    check(chain.first?.name.contains("selftest") == true, "name: \(chain.first?.name ?? "-")")
}

// MARK: - Secure Enclave identity and live agent

print("Secure Enclave identity and live agent")

test("identity: permissions, no overwrite, no default directory") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("agent"))
    let identity = try IdentityStore.createWithoutUserPresenceForTesting(in: paths)

    func mode(_ url: URL) -> Int {
        ((try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int) ?? -1
    }
    check(mode(paths.directory) == 0o700, "directory 0700")
    check(mode(paths.keyFile) == 0o600, "blob 0600")
    check(mode(paths.publicKeyFile) == 0o644, "public key 0644")
    check(throwsError { try IdentityStore.createWithoutUserPresenceForTesting(in: paths) }, "does not overwrite")
    check(throwsError {
        try IdentityStore.createWithoutUserPresenceForTesting(in: AgentPaths(directory: AgentPaths.defaultDirectory))
    }, "test key never in the default directory")

    let loaded = try IdentityStore.load(from: paths)
    check(loaded?.publicKeyBlob == identity.publicKeyBlob, "reloads the same key")
    check(loaded?.comment == "touchid-ssh-agent-test", "comment comes from the .pub")

    let keyBytes = try Data(contentsOf: paths.keyFile)
    check(!keyBytes.isEmpty && keyBytes != identity.publicKeyBlob, "file holds only the Secure Enclave blob")

    try IdentityStore.delete(from: paths)
    check(try IdentityStore.load(from: paths) == nil, "deleted")
    check(!FileManager.default.fileExists(atPath: paths.publicKeyFile.path), ".pub removed")
}

/// Records the reasons passed to the signer so tests can inspect the prompt text.
final class RecordingSigner {
    private let lock = NSLock()
    private var storage: [String] = []
    var reasons: [String] { lock.lock(); defer { lock.unlock() }; return storage }

    func signer(failingWith error: SignError? = nil) -> AgentServer.Signer {
        { [self] data, identity, reason in
            lock.lock()
            storage.append(reason)
            lock.unlock()
            if let error { throw error }
            return try SecureEnclaveSigner.sign(data, with: identity, reason: reason)
        }
    }
}

struct LiveAgent {
    let directory: URL
    let paths: AgentPaths
    let identity: StoredIdentity
    let server: AgentServer
    let recorder: RecordingSigner
    var socket: String { paths.socket.path }
    var environment: [String: String] { ["SSH_AUTH_SOCK": socket] }

    static func start(failingWith error: SignError? = nil) throws -> LiveAgent {
        let directory = try makeTempDirectory()
        do {
            let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
            let identity = try IdentityStore.createWithoutUserPresenceForTesting(in: paths)
            let recorder = RecordingSigner()
            let server = AgentServer(
                paths: paths,
                log: EventLog(url: paths.logFile, echoToStderr: false),
                signer: recorder.signer(failingWith: error)
            )
            try server.start()
            return LiveAgent(directory: directory, paths: paths, identity: identity, server: server, recorder: recorder)
        } catch {
            // e.g. Secure Enclave refuses while the screen is locked.
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func stop() {
        server.stop()
        try? FileManager.default.removeItem(at: directory)
    }

    /// `ssh-keygen -Y sign` through the agent; returns the signature file if any.
    func sshsigSign(_ message: String, tag: String) throws -> (result: CommandResult, signature: URL, message: URL) {
        let messageFile = directory.appendingPathComponent("msg-\(tag)")
        try message.write(to: messageFile, atomically: true, encoding: .utf8)
        let result = try run("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", paths.publicKeyFile.path, "-n", "file", messageFile.path], environment: environment)
        return (result, messageFile.appendingPathExtension("sig"), messageFile)
    }

    func sshsigVerify(signature: URL, message: URL) throws -> CommandResult {
        let signers = directory.appendingPathComponent("allowed_signers")
        try "test@local \(identity.authorizedKeyLine)\n".write(to: signers, atomically: true, encoding: .utf8)
        return try run("/usr/bin/ssh-keygen", ["-Y", "verify", "-f", signers.path, "-I", "test@local", "-n", "file", "-s", signature.path],
                       stdin: try Data(contentsOf: message))
    }
}

test("socket 0600 and ssh-add -L lists exactly the identity") {
    let agent = try LiveAgent.start()
    defer { agent.stop() }
    let mode = (try? FileManager.default.attributesOfItem(atPath: agent.socket))?[.posixPermissions] as? Int
    check(mode == 0o600, "socket 0600: \(String(mode ?? -1, radix: 8))")
    let result = try run("/usr/bin/ssh-add", ["-L"], environment: agent.environment)
    check(result.status == 0, "ssh-add -L: \(result.stderr)")
    check(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == agent.identity.authorizedKeyLine, "same line: \(result.stdout)")
    let fingerprints = try run("/usr/bin/ssh-add", ["-l"], environment: agent.environment)
    check(fingerprints.stdout.contains(agent.identity.fingerprint), "ssh-add -l shows the fingerprint")
}

test("OpenSSH verifies the Secure Enclave signature (ssh-keygen -Y)") {
    let agent = try LiveAgent.start()
    defer { agent.stop() }
    let (result, signature, message) = try agent.sshsigSign("signed content", tag: "ok")
    check(result.status == 0, "signed: \(result.stderr)")
    let verify = try agent.sshsigVerify(signature: signature, message: message)
    check(verify.status == 0 && verify.stdout.contains("Good"), "verified: \(verify.stdout) \(verify.stderr)")
    check(agent.recorder.reasons.first?.hasPrefix("sign data (file), requested by ssh-keygen") == true,
          "prompt: \(agent.recorder.reasons.first ?? "-")")

    // A tampered message must not verify with the same signature.
    try "tampered content".write(to: message, atomically: true, encoding: .utf8)
    check(try agent.sshsigVerify(signature: signature, message: message).status != 0, "tampering detected")
}

test("Touch ID denied: no signature") {
    for error in [SignError.canceled, .timedOut, .biometryLockout] {
        let agent = try LiveAgent.start(failingWith: error)
        defer { agent.stop() }
        let (result, signature, _) = try agent.sshsigSign("must not be signed", tag: "deny")
        check(result.status != 0, "\(error.logCode): ssh-keygen failed")
        check(!FileManager.default.fileExists(atPath: signature.path), "\(error.logCode): no .sig file")
        let log = (try? String(contentsOf: agent.paths.logFile, encoding: .utf8)) ?? ""
        check(log.contains("denied kind=sshsig") && log.contains("why=\(error.logCode)"), "log records the denial: \(log)")
    }
}

test("concurrent signatures are serialized and all valid") {
    let agent = try LiveAgent.start()
    defer { agent.stop() }
    let group = DispatchGroup()
    let lock = NSLock()
    var outcomes: [(CommandResult, URL, URL)] = []
    for index in 0..<8 {
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            if let outcome = try? agent.sshsigSign("message \(index)", tag: "c\(index)") {
                lock.lock(); outcomes.append(outcome); lock.unlock()
            }
        }
    }
    group.wait()
    check(outcomes.count == 8, "8 runs")
    for (result, signature, message) in outcomes {
        check(result.status == 0, "signed")
        check((try? agent.sshsigVerify(signature: signature, message: message))?.status == 0, "verified")
    }
}

test("unsupported messages, wrong key and garbage") {
    let agent = try LiveAgent.start()
    defer { agent.stop() }
    check(AgentClient.roundTrip(socketPath: agent.socket, body: Data([17])) == AgentProtocol.failure, "add key → failure")
    check(AgentClient.roundTrip(socketPath: agent.socket, body: Data([19])) == AgentProtocol.failure, "remove key → failure")
    var ext = SSHWriter()
    ext.writeByte(27)
    ext.writeString("session-bind@openssh.com")
    check(AgentClient.roundTrip(socketPath: agent.socket, body: ext.data) == AgentProtocol.failure, "extension → failure")

    var wrongKey = SSHWriter()
    wrongKey.writeByte(13)
    wrongKey.writeString(SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey))
    wrongKey.writeString(Data("x".utf8))
    wrongKey.writeUInt32(0)
    check(AgentClient.roundTrip(socketPath: agent.socket, body: wrongKey.data) == AgentProtocol.failure, "unknown key → failure")
    check(agent.recorder.reasons.isEmpty, "no prompt for an unknown key")

    // Oversized frame: the agent drops the connection without answering.
    if let fd = AgentClient.connect(socketPath: agent.socket) {
        _ = Data([0x7F, 0xFF, 0xFF, 0xFF]).withUnsafeBytes { write(fd, $0.baseAddress, 4) }
        var byte: UInt8 = 0
        check(read(fd, &byte, 1) == 0, "connection closed")
        close(fd)
    }
    check(AgentClient.listIdentities(socketPath: agent.socket)?.count == 1, "agent still alive")
}

test("a second agent on the same socket is refused; stop removes the socket") {
    let agent = try LiveAgent.start()
    let second = AgentServer(paths: agent.paths, log: EventLog(url: nil, echoToStderr: false))
    check(throwsError { try second.start() }, "second agent refused")
    agent.server.stop()
    check(!FileManager.default.fileExists(atPath: agent.socket), "socket removed")
    try? FileManager.default.removeItem(at: agent.directory)
}

test("log has no key, user or payload") {
    let agent = try LiveAgent.start()
    defer { agent.stop() }
    _ = try agent.sshsigSign("secret-in-payload", tag: "log")
    let log = (try? String(contentsOf: agent.paths.logFile, encoding: .utf8)) ?? ""
    check(log.contains("approved kind=sshsig requester=ssh-keygen"), "records the approval: \(log)")
    check(!log.contains(agent.identity.publicKeyBlob.base64EncodedString()), "no public key")
    check(!log.contains("secret-in-payload"), "no payload")
}

// MARK: - Docker end-to-end

if runDocker {
    print("Real SSH login against an sshd container (Docker)")

    let image = "touchid-ssh-agent-e2e:local"
    let dockerfileDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("e2e")
    let docker = ["/usr/local/bin/docker", "/opt/homebrew/bin/docker"].first { FileManager.default.isExecutableFile(atPath: $0) } ?? "docker"

    func ssh(_ agent: LiveAgent, port: String, command: String) throws -> CommandResult {
        try run("/usr/bin/ssh", [
            "-F", "/dev/null",
            "-o", "IdentityAgent=\(agent.socket)",
            "-o", "IdentityFile=\(agent.paths.publicKeyFile.path)",
            "-o", "IdentitiesOnly=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=\(agent.directory.appendingPathComponent("known_hosts").path)",
            "-p", port, "tester@127.0.0.1", command,
        ])
    }

    var container: String?
    test("builds the sshd container") {
        let build = try run(docker, ["build", "-q", "-t", image, dockerfileDirectory.path])
        check(build.status == 0, "docker build: \(build.stderr)")
    }

    let approving = try LiveAgent.start()
    let denying = try LiveAgent.start(failingWith: .canceled)
    defer {
        approving.stop()
        denying.stop()
        if let container { _ = try? run(docker, ["rm", "-f", container]) }
    }

    var port = ""
    test("container accepts only the agent keys") {
        let keys = approving.identity.authorizedKeyLine + "\n" + denying.identity.authorizedKeyLine
        let started = try run(docker, ["run", "-d", "--rm", "-p", "127.0.0.1::22", "-e", "AUTHORIZED_KEYS=\(keys)", image])
        check(started.status == 0, "docker run: \(started.stderr)")
        container = started.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let mapped = try run(docker, ["port", container ?? "", "22/tcp"])
        port = mapped.stdout.split(separator: "\n").first?.split(separator: ":").last.map(String.init) ?? ""
        check(!port.isEmpty, "mapped port: \(mapped.stdout)")
        for _ in 0..<50 {
            if (try? run("/usr/bin/nc", ["-z", "127.0.0.1", port]))?.status == 0 { break }
            usleep(100_000)
        }
        usleep(500_000)
    }

    test("approved SSH login works without a private key file") {
        let result = try ssh(approving, port: port, command: "echo login-ok-$(whoami)")
        check(result.status == 0, "ssh exited with \(result.status): \(result.stderr)")
        check(result.stdout.contains("login-ok-tester"), "output: \(result.stdout)")
        let reason = approving.recorder.reasons.last ?? "-"
        check(reason.hasPrefix("log in over SSH as tester to a server not in known_hosts"), "prompt: \(reason)")
        check(reason.contains("requested by ssh"), "requester: \(reason)")
        let log = (try? String(contentsOf: approving.paths.logFile, encoding: .utf8)) ?? ""
        check(log.contains("approved kind=login-hostbound requester=ssh"), "log: \(log)")
    }

    test("denied Touch ID blocks the login") {
        let result = try ssh(denying, port: port, command: "echo should-not-run")
        check(result.status != 0, "ssh should fail")
        check(!result.stdout.contains("should-not-run"), "no command ran")
        check(denying.recorder.reasons.count == 1, "a single prompt, denied")
    }
} else {
    print("(real Docker login skipped; use --docker)")
}

// MARK: - Summary

print("")
if failed.isEmpty {
    print("OK: \(passed) tests passed.")
    exit(0)
}
print("FAILED: \(failed.count) check(s); \(passed) tests passed.")
failed.forEach { print("  - \($0)") }
exit(1)

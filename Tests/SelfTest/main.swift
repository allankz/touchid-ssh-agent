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
    var passedCheck = false
    var detail = ""
    do {
        passedCheck = try condition()
    } catch {
        detail = " — threw: \(error)"
    }
    if !passedCheck {
        failed.append("\(currentTest): \(message)\(detail) (line \(line))")
        print("    ✗ \(message)\(detail) (line \(line))")
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

struct ShellResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

@discardableResult
func run(_ executable: String, _ arguments: [String], environment: [String: String] = [:], stdin: Data? = nil) throws -> ShellResult {
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
    return ShellResult(
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

test("safe comments keep shell-safe characters only") {
    check(RemoteKeys.safeComment("touchid-recovery@mac") == "touchid-recovery@mac", "kept")
    check(RemoteKeys.safeComment("a'b; rm -rf /") == "a-b--rm--rf--", "quotes, spaces and slashes replaced")
    check(RemoteKeys.safeComment("") == "key", "empty")
    check(RemoteKeys.safeComment(String(repeating: "x", count: 200)).count == 80, "truncated")
}

test("install script appends each key once and reports through markers") {
    let login = AuthorizedKey(label: "login", type: SSHKeyFormat.keyType,
                              blob: SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey), comment: "me@mac")
    let recovery = AuthorizedKey(label: "recovery", type: "ssh-ed25519", blob: Data([1, 2, 3]), comment: "it's me")
    let script = RemoteKeys.installScript([login, recovery])
    check(script.contains("grep -qF '\(login.base64)'"), "login idempotency check")
    check(script.contains("printf '%s\\n' '\(recovery.line)'"), "recovery line appended")
    check(recovery.comment == "it-s-me", "comment sanitized before quoting")
    check(script.contains("tail -c 1"), "fixes a missing final newline")
    let report = RemoteKeys.parse("Welcome!\nTOUCHID-SSH-AGENT added login\nnoise TOUCHID-SSH-AGENT x\nTOUCHID-SSH-AGENT present recovery\n")
    check(report == ["login": "added", "recovery": "present"], "parse ignores shell noise: \(report)")
}

test("generated passphrases: 6 groups of 4 unambiguous characters") {
    var seen = Set<String>()
    for _ in 0..<200 {
        let passphrase = Passphrase.generate()
        let groups = passphrase.split(separator: "-")
        check(groups.count == 6 && groups.allSatisfy { $0.count == 4 }, "shape: \(passphrase)")
        check(passphrase.allSatisfy { $0 == "-" || Passphrase.alphabet.contains($0) }, "alphabet: \(passphrase)")
        seen.insert(passphrase)
    }
    check(seen.count == 200, "no repeats")
}

test("emergency public keys: ed25519 and rsa only, never a private key") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    for type in ["ed25519", "rsa", "ecdsa"] {
        let file = directory.appendingPathComponent(type)
        try run("/usr/bin/ssh-keygen", ["-q", "-t", type, "-N", "", "-C", "old key", "-f", file.path])
        let line = try String(contentsOf: file.appendingPathExtension("pub"), encoding: .utf8)
        if type == "ecdsa" {
            check(throwsError { _ = try RecoveryKey(line: line) }, "ecdsa rejected")
        } else {
            let key = try RecoveryKey(line: line)
            let listed = try run("/usr/bin/ssh-keygen", ["-lf", file.appendingPathExtension("pub").path]).stdout
            check(listed.contains(key.fingerprint), "\(type) fingerprint matches ssh-keygen")
            check(key.comment == "old-key", "\(type) comment sanitized")
        }
        check(throwsError { _ = try RecoveryKey(line: try String(contentsOf: file, encoding: .utf8)) }, "\(type) private key rejected")
    }
    let ed = try String(contentsOf: directory.appendingPathComponent("ed25519.pub"), encoding: .utf8)
    check(throwsError { _ = try RecoveryKey(line: ed.replacingOccurrences(of: "ssh-ed25519", with: "ssh-rsa")) }, "type mismatch rejected")
}

test("inventory and settings: round trip, upsert by alias, mode 0600") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    check(try InventoryStore.load(from: paths).servers.isEmpty, "missing file is an empty inventory")
    var inventory = Inventory(mac: "test")
    let entry = InventoryEntry(alias: "web", destination: "web", hostname: "server.example", user: "deploy", port: 22,
                               sshConfigFile: nil, loginKeyFingerprint: "SHA256:a", recoveryKeyFingerprint: "SHA256:b",
                               authorizedAt: Date(timeIntervalSince1970: 1_800_000_000))
    inventory.upsert(entry)
    var moved = entry
    moved.port = 2222
    inventory.upsert(moved)
    check(inventory.servers.count == 1 && inventory.servers[0].port == 2222, "upsert replaces")
    try InventoryStore.save(inventory, to: paths)
    check(try InventoryStore.load(from: paths) == inventory, "round trip")
    let mode = (try? FileManager.default.attributesOfItem(atPath: paths.inventoryFile.path))?[.posixPermissions] as? Int
    check(mode == 0o600, "inventory 0600")

    check(SettingsStore.load(from: paths) == AgentSettings(), "default settings")
    try SettingsStore.save(AgentSettings(backupPath: "/tmp/x"), to: paths)
    check(SettingsStore.load(from: paths).backupPath == "/tmp/x", "settings round trip")
}

test("authorize gives up quickly when the server does not answer") {
    // 192.0.2.0/24 is reserved for documentation and never answers.
    let started = Date()
    let target = SSHTarget(destination: "tester@192.0.2.1", configFile: "/dev/null")
    let key = AuthorizedKey(label: "login", type: "ssh-ed25519", blob: Data([1]), comment: "x")
    check(throwsError { _ = try RemoteKeys.install([key], on: target) }, "install fails")
    let elapsed = Date().timeIntervalSince(started)
    check(elapsed < Double(SSHTarget.connectTimeout + 15), "failed within the connect timeout: \(Int(elapsed))s")
}

// MARK: - Emergency kit and inventory backup

print("Emergency kit and inventory backup")

let agePath = Command.find("age")

test("emergency kit: opens with the passphrase, instructions after the key, nothing left behind") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    let passphrase = Passphrase.generate()
    let details = EmergencyKitBuilder.Details(macName: "testmac", loginKeyFingerprint: "SHA256:login",
                                              backupFolder: "~/Library/Mobile Documents/backup")
    let kit = try EmergencyKitBuilder.build(passphrase: passphrase, details: details, paths: paths)
    let text = try String(contentsOf: kit.file, encoding: .utf8)
    // Markers built in pieces so secret scanners do not flag this test.
    let pemLabel = "OPENSSH " + "PRIVATE KEY-----"
    check(text.hasPrefix("-----BEGIN " + pemLabel), "key block first")
    let afterKey = text.components(separatedBy: "-----END " + pemLabel).last ?? ""
    check(afterKey.contains("EMERGENCY KIT") && afterKey.contains(kit.recoveryKey.fingerprint), "instructions after the key")
    check(afterKey.contains("SHA256:login") && afterKey.contains("Mobile Documents/backup/inventory.age"), "fingerprints and backup folder")
    check(kit.recoveryKey.comment == "touchid-recovery@testmac", "key comment: \(kit.recoveryKey.comment)")
    let mode = (try? FileManager.default.attributesOfItem(atPath: kit.file.path))?[.posixPermissions] as? Int
    check(mode == 0o600, "kit 0600")
    check((try? FileManager.default.contentsOfDirectory(atPath: paths.kitDirectory.path)) == [EmergencyKitBuilder.kitFileName]
          || (try? FileManager.default.contentsOfDirectory(atPath: paths.kitDirectory.path).sorted()) == [EmergencyKitBuilder.kitFileName],
          "only the kit file, no raw key: \((try? FileManager.default.contentsOfDirectory(atPath: paths.kitDirectory.path)) ?? [])")

    check((try? EmergencyKitBuilder.verify(kitFile: kit.file, passphrase: passphrase, expected: kit.recoveryKey)) != nil, "right passphrase opens it")
    check(throwsError { try EmergencyKitBuilder.verify(kitFile: kit.file, passphrase: "wrong", expected: kit.recoveryKey) }, "wrong passphrase fails")
    check(throwsError { try EmergencyKitBuilder.verify(kitFile: kit.file, passphrase: passphrase.uppercased(), expected: kit.recoveryKey) },
          "passphrase is exact")

    try EmergencyKitBuilder.finalize(kit, paths: paths, replace: false)
    check(!FileManager.default.fileExists(atPath: paths.kitDirectory.path), "kit scratch directory erased")
    check(try RecoveryStore.load(from: paths) == kit.recoveryKey, "recovery.pub installed")
    check(throwsError { try RecoveryStore.install(kit.recoveryKey, in: paths, replace: false) }, "refuses to replace without --replace")
}

/// An unencrypted ed25519 key wrapped like a kit (key block, then text), so
/// tests can decrypt and log in without typing a passphrase.
func plainKit(in directory: URL, name: String) throws -> (kit: URL, publicKey: URL) {
    let key = directory.appendingPathComponent(name)
    try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key.path])
    let kit = directory.appendingPathComponent("\(name)-kit.txt")
    try (try String(contentsOf: key, encoding: .utf8) + "\nTOUCHID-SSH-AGENT EMERGENCY KIT\ntext after the key\n")
        .write(to: kit, atomically: true, encoding: .utf8)
    chmod(kit.path, 0o600)
    return (kit, key.appendingPathExtension("pub"))
}

test("inventory backup: age decrypts it with the kit, other keys cannot, re-encrypted on key change") {
    guard let age = agePath else {
        check(false, "age is not installed (brew install age)")
        return
    }
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    let folder = directory.appendingPathComponent("cloud folder")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
    let settings = AgentSettings(backupPath: folder.path)

    check(InventoryBackup.export(paths: paths, settings: AgentSettings()) == .noBackupFolder, "no folder")
    check(InventoryBackup.export(paths: paths, settings: settings) == .noRecoveryKey, "no emergency key")

    let first = try plainKit(in: directory, name: "first")
    let second = try plainKit(in: directory, name: "second")
    try RecoveryStore.importPublicKey(from: first.publicKey, into: paths, replace: false)
    var inventory = Inventory(mac: "test")
    inventory.upsert(InventoryEntry(alias: "web", destination: "web", hostname: "server.example", user: "deploy", port: 22,
                                    sshConfigFile: nil, loginKeyFingerprint: "SHA256:a", recoveryKeyFingerprint: "SHA256:b",
                                    authorizedAt: Date()))
    try InventoryStore.save(inventory, to: paths)

    let outcome = InventoryBackup.export(paths: paths, settings: settings)
    let backup = folder.appendingPathComponent(InventoryBackup.fileName)
    check(outcome == .written(backup), "written: \(outcome)")
    let raw = (try? Data(contentsOf: backup)) ?? Data()
    check(!String(decoding: raw, as: UTF8.self).contains("server.example"), "encrypted at rest")
    let decrypted = try run(age, ["-d", "-i", first.kit.path, backup.path])
    check(decrypted.status == 0 && decrypted.stdout.contains("server.example"), "the kit decrypts it: \(decrypted.stderr)")
    check(try run(age, ["-d", "-i", second.kit.path, backup.path]).status != 0, "another key cannot")
    let readme = (try? String(contentsOf: folder.appendingPathComponent(InventoryBackup.readmeName), encoding: .utf8)) ?? ""
    check(readme.contains("age -d -i emergency-kit.txt inventory.age") && !readme.contains("server.example"),
          "README explains decryption and names no server")

    try RecoveryStore.importPublicKey(from: second.publicKey, into: paths, replace: true)
    InventoryBackup.export(paths: paths, settings: settings)
    check(try run(age, ["-d", "-i", second.kit.path, backup.path]).status == 0, "new kit decrypts the re-exported backup")
    check(try run(age, ["-d", "-i", first.kit.path, backup.path]).status != 0, "old kit no longer does")
    let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
    check(leftovers.sorted() == [InventoryBackup.readmeName, InventoryBackup.fileName].sorted(), "no temp files: \(leftovers)")
}

test("inventory backup: an existing file is never replaced by an empty inventory") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let folder = directory.appendingPathComponent("cloud")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
    let settings = AgentSettings(backupPath: folder.path)
    let backup = folder.appendingPathComponent(InventoryBackup.fileName)

    // The old Mac's backup, with one server.
    let oldMac = AgentPaths(directory: directory.appendingPathComponent("old-mac"))
    let oldKit = try plainKit(in: directory, name: "old")
    try RecoveryStore.importPublicKey(from: oldKit.publicKey, into: oldMac, replace: false)
    var inventory = Inventory(mac: "old")
    inventory.upsert(InventoryEntry(alias: "web", destination: "web", hostname: "server.example", user: "deploy", port: 22,
                                    sshConfigFile: nil, loginKeyFingerprint: "SHA256:a", recoveryKeyFingerprint: "SHA256:b",
                                    authorizedAt: Date()))
    try InventoryStore.save(inventory, to: oldMac)
    check(InventoryBackup.export(paths: oldMac, settings: settings) == .written(backup), "old Mac writes its backup")
    let original = try Data(contentsOf: backup)

    // A new Mac with a new emergency key and no servers yet must not replace it.
    let newMac = AgentPaths(directory: directory.appendingPathComponent("new-mac"))
    let newKit = try plainKit(in: directory, name: "new")
    try RecoveryStore.importPublicKey(from: newKit.publicKey, into: newMac, replace: false)
    check(InventoryBackup.export(paths: newMac, settings: settings) == .keptExisting(backup), "empty inventory keeps the file")
    check((try? Data(contentsOf: backup)) == original, "backup unchanged")

    // Once the new Mac has servers, it replaces the backup as usual.
    try InventoryStore.save(inventory, to: newMac)
    check(InventoryBackup.export(paths: newMac, settings: settings) == .written(backup), "non-empty inventory writes")
    check((try? Data(contentsOf: backup)) != original, "backup replaced")
}

// MARK: - CLI, driven through a real terminal with expect

print("CLI (interactive flows through expect)")

/// The CLI binary next to this test binary (`swift build` builds both).
let cliBinary = Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("touchid-ssh-agent").path

/// Runs an expect script; `$env(CLI)` is the CLI and the agent directory is `paths`.
func expectScript(_ body: String, paths: AgentPaths, extra: [String: String] = [:], in directory: URL) throws -> ShellResult {
    let script = directory.appendingPathComponent("script-\(UUID().uuidString).exp")
    try ("set timeout 90\nlog_user 1\n" + body).write(to: script, atomically: true, encoding: .utf8)
    var environment = ["CLI": cliBinary, AgentPaths.environmentVariable: paths.directory.path, "TOUCHID_SSH_AGENT_NO_REVEAL": "1"]
    environment.merge(extra) { $1 }
    return try run("/usr/bin/expect", ["-f", script.path], environment: environment)
}

/// expect fragment: reads the generated passphrase into $pass and retypes it.
let confirmPassphrase = #"""
expect {
  -re {([2-9a-z]{4}(-[2-9a-z]{4}){5})} { set pass $expect_out(1,string) }
  timeout { puts "NO_PASSPHRASE"; exit 2 }
}
expect "Retype the passphrase"
send -- "$pass\r"
expect "Passphrase confirmed."
"""#

test("recovery create: passphrase shown once and retyped, kit saved, nothing left on the Mac") {
    guard FileManager.default.isExecutableFile(atPath: cliBinary) else {
        check(false, "CLI not built: run `swift build` first")
        return
    }
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    let copy = directory.appendingPathComponent("saved-kit.txt")
    let result = try expectScript(#"""
    spawn $env(CLI) recovery create
    """# + "\n" + confirmPassphrase + #"""

    expect "Type SAVED"
    exec cp $env(KIT) $env(COPY)
    send -- "SAVED\r"
    expect eof
    puts "\nPASS=$pass"
    """#, paths: paths, extra: ["KIT": paths.kitDirectory.appendingPathComponent(EmergencyKitBuilder.kitFileName).path,
                                 "COPY": copy.path], in: directory)
    let passphrase = result.stdout.components(separatedBy: "PASS=").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    check(result.status == 0 && passphrase.count == 29, "flow completed: \(result.stdout.suffix(300))")
    check(result.stdout.contains("Emergency key configured"), "configured")
    let key = try RecoveryStore.load(from: paths)
    check(key != nil, "recovery.pub installed")
    check(!FileManager.default.fileExists(atPath: paths.kitDirectory.path), "kit erased from the Mac")
    if let key {
        check((try? EmergencyKitBuilder.verify(kitFile: copy, passphrase: passphrase, expected: key)) != nil,
              "the saved kit opens with the passphrase that was shown")
    }
    check(!result.stdout.contains(passphrase) || result.stdout.components(separatedBy: passphrase).count == 3,
          "passphrase printed once (plus the test's own PASS= line)")
}

test("recovery create: three wrong retypes or ABORT configure nothing") {
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    let wrong = try expectScript(#"""
    spawn $env(CLI) recovery create
    expect -re {([2-9a-z]{4}(-[2-9a-z]{4}){5})}
    for {set i 0} {$i < 3} {incr i} { expect "Retype the passphrase"; send -- "wrong\r" }
    expect eof
    """#, paths: paths, in: directory)
    check(wrong.stdout.contains("Nothing was created"), "mismatch aborts: \(wrong.stdout.suffix(200))")
    check(try RecoveryStore.load(from: paths) == nil, "no emergency key after mismatch")

    let aborted = try expectScript(#"""
    spawn $env(CLI) recovery create
    """# + "\n" + confirmPassphrase + #"""

    expect "Type SAVED"
    send -- "ABORT\r"
    expect eof
    """#, paths: paths, in: directory)
    check(aborted.stdout.contains("Aborted. The kit was erased"), "abort: \(aborted.stdout.suffix(200))")
    check(try RecoveryStore.load(from: paths) == nil, "no emergency key after abort")
    check(!FileManager.default.fileExists(atPath: paths.kitDirectory.path), "kit erased after abort")
}

test("recover refuses another directory on a Mac whose main key is in the inventory") {
    let mainPaths = AgentPaths(directory: AgentPaths.defaultDirectory)
    guard let main = try? IdentityStore.load(from: mainPaths) else {
        print("    (skipped: this Mac has no main identity)")
        return
    }
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    try IdentityStore.createWithoutUserPresenceForTesting(in: paths)
    let kit = try plainKit(in: directory, name: "kit")
    let folder = directory.appendingPathComponent("cloud")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
    let source = AgentPaths(directory: directory.appendingPathComponent("source"))
    try RecoveryStore.importPublicKey(from: kit.publicKey, into: source, replace: false)
    var inventory = Inventory(mac: "this mac")
    inventory.upsert(InventoryEntry(alias: "web", destination: "web", hostname: "server.example", user: "deploy", port: 22,
                                    sshConfigFile: nil, loginKeyFingerprint: main.fingerprint, recoveryKeyFingerprint: "SHA256:x",
                                    authorizedAt: Date()))
    try InventoryStore.save(inventory, to: source)
    InventoryBackup.export(paths: source, settings: AgentSettings(backupPath: folder.path))
    let result = try expectScript(#"""
    spawn $env(CLI) recover $env(KIT) --inventory $env(INV)
    expect eof
    catch wait result
    puts "\nEXIT=[lindex $result 3]"
    """#, paths: paths, extra: ["KIT": kit.kit.path, "INV": folder.appendingPathComponent(InventoryBackup.fileName).path], in: directory)
    check(result.stdout.contains("main Touch ID key") && result.stdout.contains("EXIT=1"), "refused: \(result.stdout.suffix(400))")
    check(!result.stdout.contains("Type RECOVER"), "stopped before touching any server")
}

test("setup: backup folder, new kit, and age opens the backup with the passphrase-protected kit") {
    guard let age = agePath else {
        check(false, "age is not installed (brew install age)")
        return
    }
    let directory = try makeTempDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
    // An existing identity, so setup does not create a Touch ID key.
    try IdentityStore.createWithoutUserPresenceForTesting(in: paths)
    let backup = directory.appendingPathComponent("cloud folder")
    let copy = directory.appendingPathComponent("saved-kit.txt")
    let result = try expectScript(#"""
    spawn $env(CLI) setup
    expect "Already created"
    expect "or 'skip': "
    send -- "$env(BACKUP)\r"
    expect "new/import"
    send -- "new\r"
    """# + "\n" + confirmPassphrase + #"""

    expect "Type SAVED"
    exec cp $env(KIT) $env(COPY)
    send -- "SAVED\r"
    expect "Next steps"
    expect eof
    spawn $env(AGE) -d -i $env(COPY) $env(BACKUP)/inventory.age
    expect "passphrase"
    send -- "$pass\r"
    expect eof
    """#, paths: paths, extra: ["BACKUP": backup.path, "AGE": age, "COPY": copy.path,
                                 "KIT": paths.kitDirectory.appendingPathComponent(EmergencyKitBuilder.kitFileName).path],
       in: directory)
    check(result.status == 0, "expect: \(result.stdout.suffix(300))")
    check(SettingsStore.load(from: paths).backupPath == backup.path, "backup folder saved")
    check(try RecoveryStore.load(from: paths) != nil, "emergency key configured")
    check(FileManager.default.fileExists(atPath: backup.appendingPathComponent(InventoryBackup.fileName).path), "inventory.age written")
    check(result.stdout.contains("\"servers\""), "age decrypted the backup with the real kit and passphrase")
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
    func sshsigSign(_ message: String, tag: String) throws -> (result: ShellResult, signature: URL, message: URL) {
        let messageFile = directory.appendingPathComponent("msg-\(tag)")
        try message.write(to: messageFile, atomically: true, encoding: .utf8)
        let result = try run("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", paths.publicKeyFile.path, "-n", "file", messageFile.path], environment: environment)
        return (result, messageFile.appendingPathExtension("sig"), messageFile)
    }

    func sshsigVerify(signature: URL, message: URL) throws -> ShellResult {
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
    var outcomes: [(ShellResult, URL, URL)] = []
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

    func ssh(_ agent: LiveAgent, port: String, command: String) throws -> ShellResult {
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

    // authorize / audit against a server that starts with a bootstrap key only.
    let work = try makeTempDirectory()
    let bootstrap = work.appendingPathComponent("bootstrap")
    try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "bootstrap", "-f", bootstrap.path])
    let bootstrapLine = try String(contentsOf: bootstrap.appendingPathExtension("pub"), encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let recoveryKit = try plainKit(in: work, name: "recovery")
    try RecoveryStore.importPublicKey(from: recoveryKit.publicKey, into: approving.paths, replace: false)
    let recoveryKey = try RecoveryStore.load(from: approving.paths)!
    let keys = [AuthorizedKey.login(approving.identity), AuthorizedKey.recovery(recoveryKey)]

    var authContainer: String?
    defer {
        if let authContainer { _ = try? run(docker, ["rm", "-f", authContainer]) }
        try? FileManager.default.removeItem(at: work)
    }
    let config = work.appendingPathComponent("ssh_config")
    let target = SSHTarget(destination: "e2e", configFile: config.path)
    var authPort = ""

    /// Runs a script on the server with the bootstrap key, independent of the agent.
    func onServer(_ script: String) throws -> String {
        try run("/usr/bin/ssh", ["-F", config.path, "-o", "IdentityAgent=none", "e2e", "sh -s"], stdin: Data(script.utf8)).stdout
    }

    test("authorize: server with a bootstrap key only, authorized_keys without a final newline") {
        let started = try run(docker, ["run", "-d", "--rm", "-p", "127.0.0.1::22", "-e", "AUTHORIZED_KEYS=\(bootstrapLine)", image])
        check(started.status == 0, "docker run: \(started.stderr)")
        authContainer = started.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        authPort = try run(docker, ["port", authContainer ?? "", "22/tcp"]).stdout
            .split(separator: "\n").first?.split(separator: ":").last.map(String.init) ?? ""
        // Probe sparingly: OpenSSH 10 penalizes sources that connect without
        // authenticating, and every container connection comes from Docker's NAT.
        for _ in 0..<50 {
            if (try? run("/usr/bin/nc", ["-z", "127.0.0.1", authPort]))?.status == 0 { break }
            usleep(100_000)
        }
        usleep(500_000)
        // The bootstrap key is a valid second identity on purpose: the Touch ID
        // check must tell which key the server actually accepted.
        try """
        Host e2e
          HostName 127.0.0.1
          Port \(authPort)
          User tester
          IdentityFile \(bootstrap.path)
          IdentitiesOnly yes
          StrictHostKeyChecking no
          UserKnownHostsFile \(work.appendingPathComponent("known_hosts").path)
          LogLevel ERROR
        """.write(to: config, atomically: true, encoding: .utf8)
        _ = try onServer("f=$HOME/.ssh/authorized_keys; c=$(cat \"$f\"); printf '%s' \"$c\" > \"$f\"")
        check(try onServer("tail -c 1 $HOME/.ssh/authorized_keys | od -An -c").contains("\\n") == false, "no final newline")
    }

    test("authorize: resolve, add both keys once, verify the Touch ID key") {
        let resolved = try RemoteKeys.resolve(target)
        check(resolved.hostname == "127.0.0.1" && resolved.user == "tester" && resolved.port == Int(authPort), "ssh -G: \(resolved)")
        check(resolved.identityFiles == [bootstrap.path] && resolved.identitiesOnly, "identity files: \(resolved.identityFiles)")
        check(resolved.userKnownHostsFiles == [work.appendingPathComponent("known_hosts").path], "known_hosts: \(resolved.userKnownHostsFiles)")
        check(resolved.knownHostsName == "[127.0.0.1]:\(authPort)", "known_hosts name: \(resolved.knownHostsName)")
        check(!resolved.usesTouchIDAgent(approving.paths), "bootstrap config does not use the agent")

        check(try RemoteKeys.install(keys, on: target) == ["login": true, "recovery": true], "both added")
        check(try RemoteKeys.install(keys, on: target) == ["login": false, "recovery": false], "second run adds nothing")
        let lines = try onServer("cat $HOME/.ssh/authorized_keys").split(separator: "\n").map(String.init)
        check(lines.count == 3, "three lines: \(lines)")
        check(lines.first == bootstrapLine, "bootstrap line intact")
        for key in keys {
            check(lines.filter { $0.contains(key.base64) }.count == 1, "\(key.label) exactly once")
        }

        let before = approving.recorder.reasons.count
        check(RemoteKeys.verifyLogin(on: target, paths: approving.paths, identity: approving.identity) == .ok,
              "Touch ID key accepted although the bootstrap key would also work")
        check(approving.recorder.reasons.count == before + 1, "exactly one Touch ID prompt")
    }

    test("emergency key logs in on its own") {
        let result = try run("/usr/bin/ssh", [
            "-F", "/dev/null", "-i", recoveryKit.kit.path, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=\(work.appendingPathComponent("known_hosts").path)",
            "-p", authPort, "tester@127.0.0.1", "echo recovery-ok",
        ])
        check(result.status == 0 && result.stdout.contains("recovery-ok"), "kit file works with ssh -i: \(result.stderr)")
    }

    test("audit: both present, then a missing emergency key, then a missing login key") {
        var outcome = RemoteKeys.audit(target, keys: keys, paths: approving.paths, identity: approving.identity)
        check(outcome == AuditOutcome(login: .ok, present: ["login": true, "recovery": true]), "all good: \(outcome)")

        _ = try onServer("f=$HOME/.ssh/authorized_keys; grep -vF '\(keys[1].base64)' \"$f\" > \"$f.new\"; mv \"$f.new\" \"$f\"")
        outcome = RemoteKeys.audit(target, keys: keys, paths: approving.paths, identity: approving.identity)
        check(outcome == AuditOutcome(login: .ok, present: ["login": true, "recovery": false]), "emergency key missing: \(outcome)")

        _ = try onServer("f=$HOME/.ssh/authorized_keys; grep -vF '\(keys[0].base64)' \"$f\" > \"$f.new\"; mv \"$f.new\" \"$f\"")
        outcome = RemoteKeys.audit(target, keys: keys, paths: approving.paths, identity: approving.identity)
        check(outcome.login != .ok, "Touch ID key no longer logs in: \(outcome.login)")
        check(outcome.present["login"] != true, "login key reported missing: \(outcome)")
    }

    test("CLI: authorize restores both keys, audit passes, inventory and backup updated") {
        let backup = work.appendingPathComponent("backup")
        let environment = [AgentPaths.environmentVariable: approving.paths.directory.path]
        let set = try run(cliBinary, ["set", "backup-path", backup.path], environment: environment)
        check(set.status == 0, "set backup-path: \(set.stderr)")

        let authorized = try run(cliBinary, ["authorize", "e2e", "-F", config.path, "--alias", "e2e-server"], environment: environment)
        check(authorized.status == 0, "authorize exit status: \(authorized.stdout) \(authorized.stderr)")
        check(authorized.stdout.contains("Touch ID key : added") && authorized.stdout.contains("emergency key: added"),
              "both keys re-added: \(authorized.stdout)")
        check(authorized.stdout.contains("✓ The server accepted the Touch ID key."), "Touch ID key verified")

        let inventory = try InventoryStore.load(from: approving.paths)
        check(inventory.servers.map(\.alias) == ["e2e-server"], "inventory entry: \(inventory.servers.map(\.alias))")
        check(inventory.servers.first?.port == Int(authPort), "resolved port stored")
        let decrypted = try run(agePath ?? "age", ["-d", "-i", recoveryKit.kit.path, backup.appendingPathComponent(InventoryBackup.fileName).path])
        check(decrypted.stdout.contains("e2e-server") && decrypted.stdout.contains("127.0.0.1"), "backup holds the entry")

        let audited = try run(cliBinary, ["audit"], environment: environment)
        check(audited.status == 0 && audited.stdout.contains("All servers have both keys."), "audit: \(audited.stdout)")
        let listed = try run(cliBinary, ["inventory"], environment: environment)
        check(listed.stdout.contains("e2e-server") && listed.stdout.contains("tester@127.0.0.1"), "inventory list: \(listed.stdout)")
    }

    test("CLI authorize shows ssh's own questions (new host key) instead of hanging") {
        // A fresh known_hosts and StrictHostKeyChecking=ask make ssh ask on the
        // terminal, which used to stop it silently (SIGTTIN) under Process.
        let asking = work.appendingPathComponent("ssh_config_ask")
        try (try String(contentsOf: config, encoding: .utf8))
            .replacingOccurrences(of: "StrictHostKeyChecking no", with: "StrictHostKeyChecking ask")
            .replacingOccurrences(of: work.appendingPathComponent("known_hosts").path,
                                  with: work.appendingPathComponent("known_hosts_ask").path)
            .write(to: asking, atomically: true, encoding: .utf8)
        let result = try expectScript(#"""
        set timeout 30
        spawn $env(CLI) authorize e2e -F $env(CFG) --alias e2e-ask
        expect {
          "continue connecting" { send -- "yes\r"; exp_continue }
          "accepted the Touch ID key" { puts "\nRESULT=ok"; exp_continue }
          "Add them?" { send -- "n\r"; exp_continue }
          timeout { puts "\nRESULT=hung"; exit 3 }
          eof
        }
        """#, paths: approving.paths, extra: ["CFG": asking.path], in: work)
        check(result.stdout.contains("continue connecting"), "ssh's host key question reached the terminal")
        check(result.stdout.contains("RESULT=ok"), "authorize finished: \(result.stdout.suffix(300))")
    }

    test("CLI authorize: a server without an alias gets a friendly name in ssh config and the inventory") {
        let friendlyConfig = work.appendingPathComponent("ssh_config_friendly")
        try """
        Host *
          UserKnownHostsFile \(work.appendingPathComponent("known_hosts").path)
          StrictHostKeyChecking no
          LogLevel ERROR
        """.write(to: friendlyConfig, atomically: true, encoding: .utf8)
        let result = try expectScript(#"""
        set timeout 60
        spawn $env(CLI) authorize tester@127.0.0.1 -p $env(PORT) -F $env(CFG) -- -i $env(BOOT) -o IdentitiesOnly=yes -o IdentityAgent=none
        expect {
          "or Enter to skip" { send -- "e2e-friendly\r"; exp_continue }
          "Add it to" { send -- "y\r"; exp_continue }
          timeout { puts "\nRESULT=hung"; exit 3 }
          eof
        }
        catch wait result
        puts "\nEXIT=[lindex $result 3]"
        """#, paths: approving.paths, extra: ["CFG": friendlyConfig.path, "PORT": authPort, "BOOT": bootstrap.path], in: work)
        check(result.stdout.contains("EXIT=0"), "authorize succeeded: \(result.stdout.suffix(400))")
        let configText = (try? String(contentsOf: friendlyConfig, encoding: .utf8)) ?? ""
        check(configText.contains("Host e2e-friendly") && configText.contains("IdentityAgent ")
              && configText.contains("IdentitiesOnly yes"), "block appended: \(configText)")
        let servers = try InventoryStore.load(from: approving.paths).servers
        let entry = servers.first { $0.alias == "e2e-friendly" }
        check(entry?.destination == "e2e-friendly", "inventory uses the friendly name")
        check(entry?.hostKeys?.isEmpty == false, "host key recorded: \(entry?.hostKeys ?? [])")
        check(servers.filter { $0.hostname == "127.0.0.1" && $0.port == Int(authPort) }.count == 1, "one entry per server")
        let login = try run("/usr/bin/ssh", ["-F", friendlyConfig.path, "-o", "BatchMode=yes", "e2e-friendly", "echo friendly-ok"])
        check(login.stdout.contains("friendly-ok"), "ssh e2e-friendly goes through the agent: \(login.stderr)")
        let audited = try run(cliBinary, ["audit", "e2e-friendly"], environment: [AgentPaths.environmentVariable: approving.paths.directory.path])
        check(audited.stdout.contains("`ssh e2e-friendly` uses the Touch ID agent"), "audit sees the ssh config: \(audited.stdout)")

        // Authorizing the same server by address again reuses the alias instead of asking.
        let again = try run(cliBinary, ["authorize", "tester@127.0.0.1", "-p", authPort, "-F", friendlyConfig.path,
                                        "--", "-i", bootstrap.path, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"],
                            environment: [AgentPaths.environmentVariable: approving.paths.directory.path])
        check(again.stdout.contains("`ssh e2e-friendly` already reaches this server"), "existing alias reused: \(again.stdout)")
        check(try InventoryStore.load(from: approving.paths).servers.map(\.alias).contains("e2e-friendly"), "inventory keeps the alias")
        let blocks = ((try? String(contentsOf: friendlyConfig, encoding: .utf8)) ?? "").components(separatedBy: "Host e2e-friendly").count - 1
        check(blocks == 1, "no duplicate Host block: \(blocks)")
    }

    // Recovery: an "old Mac" authorizes a fresh server, then "new Macs" take it over.
    var recContainer: String?
    let oldMac = try LiveAgent.start()
    defer {
        oldMac.stop()
        if let recContainer { _ = try? run(docker, ["rm", "-f", recContainer]) }
    }
    let recConfig = work.appendingPathComponent("ssh_config_rec")
    let newConfig = work.appendingPathComponent("ssh_config_new")
    let newKnownHosts = work.appendingPathComponent("known_hosts_new")
    let recCloud = work.appendingPathComponent("rec cloud")
    let recBackup = recCloud.appendingPathComponent(InventoryBackup.fileName)
    let oldKitFile = work.appendingPathComponent("old-emergency-kit.txt")
    let oldPassphrase = Passphrase.generate()
    var recPort = ""
    var oldKeys: [AuthorizedKey] = []

    func onRecServer(_ script: String) throws -> String {
        try run("/usr/bin/ssh", ["-F", recConfig.path, "-o", "IdentityAgent=none", "rec", "sh -s"], stdin: Data(script.utf8)).stdout
    }
    func recServerBlobs() throws -> [Data] {
        try onRecServer("cat $HOME/.ssh/authorized_keys").split(separator: "\n")
            .compactMap { RemoteKeys.keyBlob(inAuthorizedKeysLine: String($0)) }
    }
    /// Drives `recover` or `recovery test` through both passphrase prompts.
    func runRecovery(_ command: String, on newMac: LiveAgent) throws -> ShellResult {
        try expectScript(#"""
        set timeout 180
        spawn $env(CLI) {*}$env(CMD) $env(KIT) --inventory $env(INV) -F $env(CFG)
        expect {
          "Enter passphrase" { send -- "$env(PASS)\r"; exp_continue }
          "Type RECOVER" { send -- "RECOVER\r"; exp_continue }
          "or Enter to skip" { send -- "\r"; exp_continue }
          "Add it to" { send -- "y\r"; exp_continue }
          "Add them?" { send -- "n\r"; exp_continue }
          timeout { puts "\nRESULT=hung"; exit 3 }
          eof
        }
        catch wait result
        puts "\nEXIT=[lindex $result 3]"
        """#, paths: newMac.paths, extra: ["CMD": command, "KIT": oldKitFile.path, "INV": recBackup.path,
                                           "CFG": newConfig.path, "PASS": oldPassphrase], in: work)
    }

    test("recovery setup: the old Mac authorizes a fresh server and backs up its inventory") {
        let started = try run(docker, ["run", "-d", "--rm", "-p", "127.0.0.1::22", "-e", "AUTHORIZED_KEYS=\(bootstrapLine)", image])
        recContainer = started.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        recPort = try run(docker, ["port", recContainer ?? "", "22/tcp"]).stdout
            .split(separator: "\n").first?.split(separator: ":").last.map(String.init) ?? ""
        for _ in 0..<50 {
            if (try? run("/usr/bin/nc", ["-z", "127.0.0.1", recPort]))?.status == 0 { break }
            usleep(100_000)
        }
        usleep(500_000)
        try """
        Host rec
          HostName 127.0.0.1
          Port \(recPort)
          User tester
          IdentityFile \(bootstrap.path)
          IdentitiesOnly yes
          StrictHostKeyChecking no
          UserKnownHostsFile \(work.appendingPathComponent("known_hosts_rec").path)
          LogLevel ERROR
        """.write(to: recConfig, atomically: true, encoding: .utf8)
        try "Host *\n  UserKnownHostsFile \(newKnownHosts.path)\n  LogLevel ERROR\n".write(to: newConfig, atomically: true, encoding: .utf8)

        // The old kit, passphrase-protected and saved like a download (0644).
        try FileManager.default.createDirectory(at: recCloud, withIntermediateDirectories: false)
        let kit = try EmergencyKitBuilder.build(
            passphrase: oldPassphrase,
            details: .init(macName: "oldmac", loginKeyFingerprint: oldMac.identity.fingerprint, backupFolder: recCloud.path),
            paths: oldMac.paths)
        try FileManager.default.copyItem(at: kit.file, to: oldKitFile)
        chmod(oldKitFile.path, 0o644)
        try EmergencyKitBuilder.finalize(kit, paths: oldMac.paths, replace: false)
        oldKeys = [AuthorizedKey.login(oldMac.identity), AuthorizedKey.recovery(kit.recoveryKey)]

        let target = SSHTarget(destination: "rec", configFile: recConfig.path)
        _ = try RemoteKeys.install(oldKeys, on: target)
        let hostKeys = HostKeys.known(for: try RemoteKeys.resolve(target))
        check(!hostKeys.isEmpty, "host key captured from known_hosts")
        var inventory = Inventory(mac: "touchid-ssh-agent@oldmac")
        inventory.upsert(InventoryEntry(alias: "rec-server", destination: "rec", hostname: "127.0.0.1", user: "tester",
                                        port: Int(recPort) ?? 0, sshConfigFile: recConfig.path,
                                        loginKeyFingerprint: oldMac.identity.fingerprint,
                                        recoveryKeyFingerprint: kit.recoveryKey.fingerprint,
                                        authorizedAt: .wholeSecondsNow, hostKeys: hostKeys))
        try InventoryStore.save(inventory, to: oldMac.paths)
        check(InventoryBackup.export(paths: oldMac.paths, settings: AgentSettings(backupPath: recCloud.path)).isWritten, "backup written")
        let blobs = try recServerBlobs()
        check(oldKeys.allSatisfy { blobs.contains($0.blob) }, "server trusts the old Mac's keys")
    }

    test("recovery test: the old kit logs in everywhere and nothing changes") {
        let before = try onRecServer("cat $HOME/.ssh/authorized_keys")
        let probe = try LiveAgent.start()
        defer { probe.stop() }
        let result = try runRecovery("recovery test", on: probe)
        check(result.stdout.contains("EXIT=0") && result.stdout.contains("opens every server"), "dry run: \(result.stdout.suffix(500))")
        check(result.stdout.contains("asked for your emergency passphrase twice"), "warns about the two prompts")
        check(try onRecServer("cat $HOME/.ssh/authorized_keys") == before, "authorized_keys unchanged")
        check(!FileManager.default.fileExists(atPath: newKnownHosts.path), "this Mac's known_hosts untouched")
    }

    test("recover: a denied Touch ID check keeps the old keys and the backup") {
        let denied = try LiveAgent.start(failingWith: .canceled)
        defer { denied.stop() }
        try RecoveryStore.importPublicKey(from: try plainKit(in: work, name: "denied-emergency").publicKey, into: denied.paths, replace: false)
        try SettingsStore.save(AgentSettings(backupPath: recCloud.path), to: denied.paths)
        let backupBefore = try Data(contentsOf: recBackup)
        let result = try runRecovery("recover", on: denied)
        check(result.stdout.contains("EXIT=1"), "recover reports the failure: \(result.stdout.suffix(500))")
        check(result.stdout.contains("Keep the old emergency kit"), "tells the user to keep the old kit")
        let blobs = try recServerBlobs()
        check(oldKeys.allSatisfy { blobs.contains($0.blob) }, "old keys are still on the server")
        check((try? Data(contentsOf: recBackup)) == backupBefore, "backup left unchanged")
    }

    test("recover: this Mac's keys in, the lost Mac's key and the used emergency key out, audit passes") {
        let newMac = try LiveAgent.start()
        defer { newMac.stop() }
        let newKit = try plainKit(in: work, name: "new-emergency")
        let newEmergency = try RecoveryStore.importPublicKey(from: newKit.publicKey, into: newMac.paths, replace: false)
        try SettingsStore.save(AgentSettings(backupPath: recCloud.path), to: newMac.paths)
        let result = try runRecovery("recover", on: newMac)
        check(result.stdout.contains("EXIT=0"), "recover succeeded: \(result.stdout.suffix(800))")
        check(result.stdout.contains("host key checked against the inventory"), "host key pinned from the inventory")
        check(result.stdout.contains("All servers have both keys."), "audit at the end passes")
        check(result.stdout.contains("you can destroy it"), "old kit retired")

        let blobs = try recServerBlobs()
        check(blobs.contains(newMac.identity.publicKeyBlob) && blobs.contains(newEmergency.blob), "new keys installed")
        check(!blobs.contains(oldKeys[0].blob), "lost Mac's key removed")
        check(!blobs.contains(oldKeys[1].blob), "used emergency key removed")
        check(blobs.contains(RemoteKeys.keyBlob(inAuthorizedKeysLine: bootstrapLine) ?? Data()), "other keys untouched")

        let entry = try InventoryStore.load(from: newMac.paths).servers.first { $0.alias == "rec-server" }
        check(entry?.loginKeyFingerprint == newMac.identity.fingerprint && entry?.recoveryKeyFingerprint == newEmergency.fingerprint,
              "inventory points to this Mac's keys")
        check((try? String(contentsOf: newConfig, encoding: .utf8))?.contains("Host rec-server") == true, "ssh config block added")
        check(((try? String(contentsOf: newKnownHosts, encoding: .utf8)) ?? "").contains("[127.0.0.1]:\(recPort)"), "host key remembered")
        let decrypted = try run(agePath ?? "age", ["-d", "-i", newKit.kit.path, recBackup.path])
        let backedUp = try? Inventory.decode(Data(decrypted.stdout.utf8))
        check(backedUp?.servers.first { $0.alias == "rec-server" }?.loginKeyFingerprint == newMac.identity.fingerprint,
              "new backup opens with the new kit and lists this Mac's key: \(decrypted.stderr)")
        let kept = ((try? FileManager.default.contentsOfDirectory(atPath: recCloud.path)) ?? []).filter { $0.hasPrefix("inventory-before-recovery-") }
        check(kept.count == 1, "previous backup preserved: \(kept)")
    }

    test("recover --keep-emergency-key on a Mac with no emergency key keeps the kit's key") {
        // The server now trusts the previous test's Mac and "new-emergency" (an
        // unencrypted kit, so no passphrase prompts). A newer Mac takes over.
        let kit = work.appendingPathComponent("new-emergency-kit.txt")
        let before = try? Inventory.decode(Data(try run(agePath ?? "age", ["-d", "-i", kit.path, recBackup.path]).stdout.utf8))
        let previousFingerprint = before?.servers.first?.loginKeyFingerprint
        check(previousFingerprint != nil, "backup lists the previous Mac's key")
        let newer = try LiveAgent.start()
        defer { newer.stop() }
        try SettingsStore.save(AgentSettings(backupPath: recCloud.path), to: newer.paths)
        let result = try expectScript(#"""
        set timeout 180
        spawn $env(CLI) recover $env(KIT) --inventory $env(INV) -F $env(CFG) --keep-emergency-key
        expect {
          "Type RECOVER" { send -- "RECOVER\r"; exp_continue }
          "or Enter to skip" { send -- "\r"; exp_continue }
          "Add it to" { send -- "n\r"; exp_continue }
          "Add them?" { send -- "n\r"; exp_continue }
          "Retype the passphrase" { puts "\nRESULT=asked-for-new-kit"; exit 4 }
          timeout { puts "\nRESULT=hung"; exit 3 }
          eof
        }
        catch wait result
        puts "\nEXIT=[lindex $result 3]"
        """#, paths: newer.paths, extra: ["KIT": kit.path, "INV": recBackup.path, "CFG": newConfig.path], in: work)
        check(result.stdout.contains("EXIT=0"), "recover succeeded without a new kit: \(result.stdout.suffix(600))")
        let kitKey = try RecoveryStore.load(from: newer.paths)
        check(kitKey?.blob == (try? RecoveryKey(line: try String(contentsOf: work.appendingPathComponent("new-emergency.pub"), encoding: .utf8)))?.blob,
              "the kit's key is this Mac's emergency key")
        let blobs = try recServerBlobs()
        check(blobs.contains(newer.identity.publicKeyBlob), "newer Mac's key installed")
        check(kitKey.map { blobs.contains($0.blob) } == true, "kept emergency key still on the server")
        check(!blobs.contains { SSHKeyFormat.fingerprint(blob: $0) == previousFingerprint }, "previous Mac's key removed")
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

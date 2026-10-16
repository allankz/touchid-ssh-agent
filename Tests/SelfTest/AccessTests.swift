// Temporary access (Phase 2) tests that need neither Docker nor a server.
// Certificates are checked with ssh-keygen as the oracle; Secure Enclave CAs
// are created without Touch ID through the testing API, in temp directories.

import CryptoKit
import Darwin
import Foundation
@_spi(Testing) import TouchIDSSHCore

/// Grant sockets sit four levels below the data directory, so tests that run
/// grants use /tmp: the per-user temp directory is too long for a Unix socket.
func makeShortTempDirectory() throws -> URL {
    var template = Array("/tmp/tsa-XXXXXX".utf8CString)
    guard let path = mkdtemp(&template) else { throw CocoaError(.fileWriteUnknown) }
    return URL(fileURLWithPath: String(cString: path))
}

/// A software P-256 CA, to test certificates without the Secure Enclave.
struct SoftwareCA {
    let key = P256.Signing.PrivateKey()
    var blob: Data { SSHKeyFormat.publicKeyBlob(key.publicKey) }
    var fingerprint: String { SSHKeyFormat.fingerprint(blob: blob) }
    func sign(_ data: Data) throws -> Data {
        try SSHKeyFormat.signatureBlob(rawRS: try key.signature(for: data).rawRepresentation)
    }
}

/// Clocks the tests move by hand.
final class ManualClock: GrantClock {
    var wall: TimeInterval
    var monotonic: TimeInterval
    init() {
        wall = Date().timeIntervalSince1970
        monotonic = 1000
    }
    var wallSeconds: TimeInterval { wall }
    var monotonicSeconds: TimeInterval { monotonic }
}

func writeCertificate(_ blob: Data, in directory: URL, name: String = "cert") throws -> URL {
    let file = directory.appendingPathComponent("\(name)-cert.pub")
    try (SSHCertificate.publicKeyLine(blob: blob, comment: "test") + "\n").write(to: file, atomically: true, encoding: .utf8)
    return file
}

/// An agent sign request for `blob`.
func signRequest(_ blob: Data, _ data: Data) -> Data {
    var writer = SSHWriter()
    writer.writeByte(13)
    writer.writeString(blob)
    writer.writeString(data)
    writer.writeUInt32(0)
    return writer.data
}

/// A userauth payload offering `blob` (as ssh does for the certificate).
func userAuthPayload(user: String, offering blob: Data, hostKey: Data? = nil) -> Data {
    var writer = SSHWriter()
    writer.writeString(Data(repeating: 0x11, count: 32))
    writer.writeByte(50)
    writer.writeString(user)
    writer.writeString("ssh-connection")
    writer.writeString(hostKey == nil ? "publickey" : "publickey-hostbound-v00@openssh.com")
    writer.writeBool(true)
    writer.writeString(SSHKeyFormat.keyTypeName(ofBlob: blob) ?? "")
    writer.writeString(blob)
    if let hostKey { writer.writeString(hostKey) }
    return writer.data
}

func sampleTarget(_ alias: String, user: String = "deploy", hostname: String = "server.example", port: Int = 22,
                  grantId: String = "20261015-a1b2c3d4e5f6", principal: String? = nil) -> AccessTarget {
    let hostKey = "\(SSHKeyFormat.keyType) \(SSHKeyFormat.publicKeyBlob(P256.Signing.PrivateKey().publicKey).base64EncodedString())"
    return AccessTarget(requested: alias, inventoryAlias: alias, targetId: String(alias.hashValue & 0xffff_ffff, radix: 16),
                        principal: principal ?? "access-\(alias)", hostname: hostname, user: user, port: port,
                        hostKeys: [hostKey], sshAlias: AccessNames.aliases(for: [alias], grantId: grantId)[0])
}

func runAccessUnitTests() {
    print("Temporary access: certificates, trust lines, names and config")

    test("uint64: round trip and truncation") {
        for value: UInt64 in [0, 1, 0xFFFF_FFFF, 0x1_0000_0000, UInt64.max] {
            var writer = SSHWriter()
            writer.writeUInt64(value)
            check(writer.data.count == 8, "8 bytes")
            var reader = SSHReader(writer.data)
            check(try reader.readUInt64() == value, "round trip \(value)")
        }
        check(SSHWriter().data.isEmpty, "empty writer")
        var short = SSHReader(Data([0, 0, 0, 0, 0, 0, 1]))
        check(throwsError { _ = try short.readUInt64() }, "7 bytes are truncated")
        var writer = SSHWriter()
        writer.writeUInt64(0x0102_0304_0506_0708)
        check(writer.data == hex("0102030405060708"), "big-endian")
    }

    test("certificate: ssh-keygen -L reads every field of a P-256-signed Ed25519 certificate") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ca = SoftwareCA()
        let issued = try CertificateIssuer.issue(
            ca: ca.blob, serial: 42, keyID: "access-20261015-2241-42", principals: ["access-b", "access-a"],
            validAfter: 1_800_000_000, validBefore: 1_800_007_200,
            criticalOptions: [.forceCommand("/usr/local/bin/backup --all")],
            extensions: [.flag("permit-pty")], sign: ca.sign)
        let file = try writeCertificate(issued.blob, in: directory)
        let listed = try run("/usr/bin/ssh-keygen", ["-Lf", file.path])
        check(listed.status == 0, "ssh-keygen accepts the certificate: \(listed.stderr)")
        let out = listed.stdout
        check(out.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"), "type: \(out)")
        check(out.contains("Public key: ED25519-CERT \(issued.fingerprint)"), "certified key fingerprint")
        check(out.contains("Signing CA: ECDSA \(ca.fingerprint) (using ecdsa-sha2-nistp256)"), "signing CA")
        check(out.contains("Key ID: \"access-20261015-2241-42\""), "key ID")
        check(out.contains("Serial: 42"), "serial")
        check(out.range(of: "Principals: \\n\\s+access-b\\n\\s+access-a\\n", options: .regularExpression) != nil, "principals in order")
        check(out.contains("force-command /usr/local/bin/backup --all"), "forced command as a nested string")
        check(out.range(of: "Extensions: \\n\\s+permit-pty\\n", options: .regularExpression) != nil, "only permit-pty")
        check(SSHCertificate.verifySignature(blob: issued.blob), "our verifier agrees")
        let parsed = try SSHCertificate.parse(issued.blob).certificate
        check(parsed.principals == ["access-b", "access-a"] && parsed.serial == 42 && parsed.validBefore == 1_800_007_200,
              "parse round trip")
        check(parsed.forceCommand == "/usr/local/bin/backup --all" && parsed.permitsPTY, "options decoded")

        let plain = try CertificateIssuer.issue(ca: ca.blob, serial: 1, keyID: "k", principals: ["p"], validAfter: 1,
                                               validBefore: 2, sign: ca.sign)
        let plainOut = try run("/usr/bin/ssh-keygen", ["-Lf", try writeCertificate(plain.blob, in: directory, name: "plain").path]).stdout
        check(plainOut.range(of: "Critical Options: \\(none\\)", options: .regularExpression) != nil
              && plainOut.range(of: "Extensions: \\(none\\)", options: .regularExpression) != nil,
              "default certificate: no options, no extensions (no PTY, no forwarding): \(plainOut)")
    }

    test("certificate: the CA signature covers every field") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ca = SoftwareCA()
        let issued = try CertificateIssuer.issue(ca: ca.blob, serial: 9, keyID: "access-x", principals: ["access-a"],
                                                validAfter: 100, validBefore: 200, sign: ca.sign)
        let signedLength = try SSHCertificate.parse(issued.blob).signedLength
        // One byte in each region: type, nonce, key, serial, principals, validity, CA key.
        for offset in [5, 40, 75, 110, signedLength - 140, signedLength - 90, signedLength - 3] {
            var tampered = issued.blob
            tampered[offset] ^= 0x01
            check(!SSHCertificate.verifySignature(blob: tampered), "tampered byte \(offset) fails our check")
            let file = try writeCertificate(tampered, in: directory, name: "t\(offset)")
            check(try run("/usr/bin/ssh-keygen", ["-Lf", file.path]).status != 0, "ssh-keygen rejects tampered byte \(offset)")
        }
        let other = SoftwareCA()
        var forged = try SSHCertificate.parse(issued.blob).certificate
        forged.signatureKey = other.blob
        check(!SSHCertificate.verifySignature(blob: try forged.encoded(signature: issued.certificate.signature!)),
              "a signature from another CA does not verify")
    }

    test("certificate: invalid fields are refused before signing; options are sorted") {
        let ca = SoftwareCA()
        func build(principals: [String] = ["p"], after: UInt64 = 1, before: UInt64 = 2,
                   critical: [CertificateOption] = [], extensions: [CertificateOption] = []) throws -> Data {
            try CertificateIssuer.issue(ca: ca.blob, serial: 1, keyID: "k", principals: principals, validAfter: after,
                                        validBefore: before, criticalOptions: critical, extensions: extensions, sign: ca.sign).blob
        }
        check(throwsError { _ = try build(principals: []) }, "no principal")
        check(throwsError { _ = try build(principals: ["a", "a"]) }, "duplicate principal")
        check(throwsError { _ = try build(principals: ["a,b"]) }, "comma in a principal")
        check(throwsError { _ = try build(after: 2, before: 2) }, "empty validity")
        check(throwsError { _ = try build(before: UInt64.max) }, "infinite validity")
        check(throwsError { _ = try build(extensions: [.flag("permit-pty"), .flag("permit-pty")]) }, "duplicate extension")
        check(throwsError { _ = try build(extensions: [.flag("permit-everything")]) }, "unknown extension")
        check(throwsError { _ = try build(extensions: [CertificateOption(name: "permit-pty", data: Data([1]))]) }, "extension with data")
        check(throwsError { _ = try build(critical: [CertificateOption(name: "force-command", data: Data("raw".utf8))]) },
              "force-command must be a nested string")
        let blob = try build(extensions: [.flag("permit-pty"), .flag("permit-agent-forwarding")])
        let names = try SSHCertificate.parse(blob).certificate.extensions.map(\.name)
        check(names == ["permit-agent-forwarding", "permit-pty"], "sorted by name: \(names)")
    }

    test("certificate: parses ssh-keygen's own certificates; malformed input never crashes") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let caKey = directory.appendingPathComponent("ca"), userKey = directory.appendingPathComponent("u")
        try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caKey.path])
        try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", userKey.path])
        let signed = try run("/usr/bin/ssh-keygen", ["-q", "-s", caKey.path, "-I", "made-by-ssh-keygen", "-n", "p1,p2", "-V", "+1h",
                                                     "-O", "clear", "-O", "force-command=/bin/true", "-O", "permit-pty", "-z", "77",
                                                     userKey.appendingPathExtension("pub").path])
        check(signed.status == 0, "ssh-keygen signed: \(signed.stderr)")
        let line = try String(contentsOf: directory.appendingPathComponent("u-cert.pub"), encoding: .utf8)
        let blob = SSHKeyFormat.blob(fromPublicKeyLine: line) ?? Data()
        let parsed = try SSHCertificate.parse(blob).certificate
        check(parsed.keyID == "made-by-ssh-keygen" && parsed.serial == 77 && parsed.principals == ["p1", "p2"], "fields")
        check(parsed.forceCommand == "/bin/true" && parsed.permitsPTY && parsed.extensions.count == 1, "options")
        check(SSHCertificate.verifySignature(blob: blob), "Ed25519 CA signature verifies")
        for length in 0..<blob.count { _ = try? SSHCertificate.parse(blob.prefix(length)) }
        for _ in 0..<5000 {
            var mutated = blob
            mutated[Int.random(in: 0..<mutated.count)] = UInt8.random(in: 0...255)
            _ = SSHCertificate.verifySignature(blob: mutated)
        }
        check(throwsError { _ = try SSHCertificate.parse(blob.prefix(blob.count - 1)) }, "truncated signature")
        check(throwsError { _ = try SSHCertificate.parse(blob + Data([0])) }, "trailing bytes")
    }

    test("authorized_keys options: quoted values, classification of CA trust lines") {
        let caBlob = SoftwareCA().blob
        let base64 = caBlob.base64EncodedString()
        func line(_ options: String) -> AuthorizedKeysLine? {
            AuthorizedKeysLine.parse("\(options) \(SSHKeyFormat.keyType) \(base64) ca@mac")
        }
        let expected = CATrust.options(principal: "access-0123")
        check(expected == #"cert-authority,principals="access-0123",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc"#,
              "installed options: \(expected)")
        let parsed = line(#"from="198.51.100.0/24,192.0.2.1",command="echo a, b",cert-authority"#)
        check(parsed?.options == [AuthorizedKeysOption(name: "from", value: "198.51.100.0/24,192.0.2.1"),
                                  AuthorizedKeysOption(name: "command", value: "echo a, b"),
                                  AuthorizedKeysOption(name: "cert-authority")], "quoted commas and spaces: \(String(describing: parsed?.options))")
        check(parsed?.blob == caBlob, "key after the options")
        check(AuthorizedKeysLine.parse("\(SSHKeyFormat.keyType) \(base64) plain")?.options.isEmpty == true, "plain key line")
        check(AuthorizedKeysLine.parse("# comment") == nil && AuthorizedKeysLine.parse(#"command="unterminated ssh-ed25519 AAAA"#) == nil,
              "comments and broken lines are skipped")

        func scope(_ options: String) -> CATrust.Scope? { line(options).map { CATrust.scope(of: $0, principal: "access-0123") } }
        check(scope(expected) == .exact, "exact")
        check(scope(expected.uppercased().replacingOccurrences(of: "ACCESS-0123", with: "access-0123")) == .exact, "names are case-insensitive")
        check(scope(#"from="192.0.2.0/24","# + expected + ",no-pty") == .narrower, "extra restrictions are compatible")
        check(scope(#"cert-authority,restrict,principals="access-0123""#) == .narrower, "restrict covers the no-* options")
        let broader: [String] = [
            "cert-authority,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc",
            #"cert-authority,principals="access-0123,access-other",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc"#,
            #"cert-authority,principals="access-0123",no-agent-forwarding,no-X11-forwarding,no-user-rc"#,
            #"cert-authority,restrict,port-forwarding,principals="access-0123""#,
            #"principals="access-0123",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc"#,
            expected + #",environment="X=1""#,
        ]
        for options in broader {
            if case .broader? = scope(options) {} else { check(false, "broader: \(options) → \(String(describing: scope(options)))") }
        }

        let retired = SoftwareCA()
        let other = SoftwareCA()
        let listing = [
            "# keys",
            "\(expected) \(SSHKeyFormat.keyType) \(base64) ca@mac",
            "\(expected) \(SSHKeyFormat.keyType) \(base64) ca@mac",
            "cert-authority \(SSHKeyFormat.keyType) \(retired.blob.base64EncodedString()) old@mac",
            #"cert-authority,principals="ops" "# + "\(SSHKeyFormat.keyType) \(other.blob.base64EncodedString()) corp-ca",
            "\(SSHKeyFormat.keyType) \(SoftwareCA().blob.base64EncodedString()) login",
        ]
        let report = CATrust.inspect(listing, caBlob: caBlob, principal: "access-0123", retiredFingerprints: [retired.fingerprint])
        check(report.lines == [.exact, .exact] && report.isScoped, "two scoped lines")
        check(report.retiredLines == 1 && report.otherAuthorities == 1, "retired and unmanaged CAs counted")
        check(report.summary.contains("2 duplicate CA lines") && report.summary.contains("retired CA")
              && report.summary.contains("1 other cert-authority line"), report.summary)
        check(!CATrust.inspect(["# none"], caBlob: caBlob, principal: "access-0123").isPresent, "missing")
        check(CATrust.installedOptions(listing, caBlob: caBlob) == expected, "installed options read back")
    }

    test("CA trust scripts: append the scoped line once, keep every byte, remove by exact key") {
        let home = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let file = home.appendingPathComponent(".ssh/authorized_keys")
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = "# my keys\n\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOther other@laptop"
        try original.write(to: file, atomically: true, encoding: .utf8)
        let ca = SoftwareCA()
        let key = CATrust.authorizedKey(caBlob: ca.blob, comment: "touchid-ssh-agent-ca@mac", principal: "access-77")
        func sh(_ script: String) throws -> ShellResult {
            try run("/bin/sh", ["-s"], environment: ["HOME": home.path], stdin: Data(script.utf8))
        }
        let first = try sh(RemoteKeys.installScript([key]) + RemoteKeys.listing)
        check(RemoteKeys.parse(first.stdout)["ca"] == "added", "added: \(first.stdout)")
        let text = try String(contentsOf: file, encoding: .utf8)
        check(text == original + "\n" + key.line + "\n", "previous bytes kept, one line appended: \(text)")
        let report = CATrust.inspect(RemoteKeys.listedLines(first.stdout), caBlob: ca.blob, principal: "access-77")
        check(report.lines == [.exact], "the listing shows the exact scope")
        check(RemoteKeys.parse(try sh(RemoteKeys.installScript([key])).stdout)["ca"] == "present", "second run adds nothing")
        check(try String(contentsOf: file, encoding: .utf8) == text, "unchanged on the second run")

        // A broader line already holding the CA is left alone and reported.
        try (original + "\ncert-authority \(SSHKeyFormat.keyType) \(ca.blob.base64EncodedString()) hand-made\n")
            .write(to: file, atomically: true, encoding: .utf8)
        let broader = try sh(RemoteKeys.installScript([key]) + RemoteKeys.listing)
        check(RemoteKeys.parse(broader.stdout)["ca"] == "present", "not appended next to a broader line")
        let broaderReport = CATrust.inspect(RemoteKeys.listedLines(broader.stdout), caBlob: ca.blob, principal: "access-77")
        check(!broaderReport.isScoped, "reported as broader: \(broaderReport.summary)")

        _ = try sh(RemoteKeys.removeScript([ca.blob]))
        check(try String(contentsOf: file, encoding: .utf8) == original + "\n", "only the CA line removed")
    }

    test("durations, grant IDs and dated aliases") {
        let durations: [(String, UInt64)] = [("30m", 1800), ("2h", 7200), ("1h30m", 5400), ("45s", 45), ("12h", 43200), ("1h1m1s", 3661)]
        for (text, seconds) in durations { check((try? AccessDuration.parse(text)) == seconds, "\(text) = \(seconds)") }
        for bad in ["", "0m", "0h0m", "13h", "12h1s", "2", "2 h", "-1h", "1d", "h", "1.5h", "2H", "1m2h", "9999999h"] {
            check(throwsError { _ = try AccessDuration.parse(bad) }, "rejected: \"\(bad)\"")
        }
        check(AccessDuration.describe(5400) == "1 hour 30 minutes" && AccessDuration.describe(60) == "1 minute", "describe")
        let id = AccessNames.newGrantId()
        check(AccessNames.isGrantId(id) && id.count == 21, "grant id: \(id)")
        check(AccessNames.newGrantId() != id, "random part")
        check(AccessNames.label("App Server!") == "app-server", "sanitized")
        check(AccessNames.label("../../etc") == "etc", "no path characters")
        check(AccessNames.label("***") == "target", "empty label")
        check(AccessNames.label(String(repeating: "a", count: 90)).count == 32, "bounded")
        let aliases = AccessNames.aliases(for: ["web", "Web", "db"], grantId: id)
        check(aliases == ["web-access-\(id)", "web-2-access-\(id)", "db-access-\(id)"], "collisions resolved: \(aliases)")
        check(aliases.allSatisfy(AccessNames.isAlias), "literal ssh_config names")
    }

    test("grant ssh_config: selects only the grant's key, pins host keys, blocks every fallback") {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = AgentPaths(directory: root.appendingPathComponent("data 100%"))
        try paths.ensureAccessDirectories()
        let grantId = "20261015-a1b2c3d4e5f6"
        let directory = GrantDirectory(paths: paths, grantId: grantId)
        try directory.create()
        var web = sampleTarget("web", user: "deploy", hostname: "203.0.113.5", port: 2222, grantId: grantId)
        web.transport = ["serveraliveinterval": "30", "connecttimeout": "7", "addressfamily": "bad value"]
        let db = sampleTarget("db", user: "agent", hostname: "203.0.113.6", grantId: grantId)
        let request = AccessRequest(grantId: grantId, dataDirectory: paths.directory.path, caFingerprint: "SHA256:x",
                                    targets: [web, db], permissions: AccessPermissions(), requestedAt: 1_800_000_000, duration: 3600)
        try request.validate()
        let text = try GrantSSHConfig.render(request, in: directory)
        try text.write(to: directory.sshConfig, atomically: true, encoding: .utf8)
        try GrantSSHConfig.knownHosts(request).write(to: directory.knownHosts, atomically: true, encoding: .utf8)

        let resolved = try run("/usr/bin/ssh", ["-G", "-F", directory.sshConfig.path, web.sshAlias])
        check(resolved.status == 0, "ssh -G accepts the file: \(resolved.stderr)")
        let values = resolved.stdout
        for expected in ["hostname 203.0.113.5", "user deploy", "port 2222", "identitiesonly yes", "batchmode yes",
                         // ssh -G prints these two before token expansion, so % is still %%.
                         "identityagent \(directory.agentSocket.path)",
                         "identityfile \(directory.publicKey.path.replacingOccurrences(of: "%", with: "%%"))",
                         "certificatefile \(directory.certificate.path.replacingOccurrences(of: "%", with: "%%"))",
                         "hostkeyalias \(web.sshAlias)", "stricthostkeychecking true",
                         "userknownhostsfile \(directory.knownHosts.path)",
                         "globalknownhostsfile /dev/null", "forwardagent no", "forwardx11 no", "clearallforwardings yes",
                         "controlmaster false", "preferredauthentications publickey",
                         "serveraliveinterval 30", "connecttimeout 7", "requesttty false"] {
            check(values.contains("\n" + expected + "\n") || values.hasPrefix(expected + "\n"), "ssh -G: \(expected)")
        }
        check(!values.contains("addressfamily bad"), "unsafe transport values are dropped")
        check(values.components(separatedBy: "\nidentityfile ").count == 2, "a single identity file")
        check(!values.contains("\ncontrolpath ") && !values.contains("\nproxycommand ") && !values.contains("\nproxyjump "),
              "no connection sharing, no proxy")
        let dbValues = try run("/usr/bin/ssh", ["-G", "-F", directory.sshConfig.path, db.sshAlias]).stdout
        check(dbValues.contains("user agent") && dbValues.contains("hostname 203.0.113.6") && dbValues.contains("port 22\n"), "second target")

        let other = try run("/usr/bin/ssh", ["-G", "-F", directory.sshConfig.path, "server.example"]).stdout
        check(other.contains("proxycommand /usr/bin/false") && other.contains("identityagent none")
              && other.contains("pubkeyauthentication false"), "an unknown name gets no route and no credentials")
        let started = Date()
        let attempt = try run("/usr/bin/ssh", ["-F", directory.sshConfig.path, "server.example", "true"])
        check(attempt.status != 0 && Date().timeIntervalSince(started) < 10, "unknown name fails at once: \(attempt.stderr)")

        let known = try String(contentsOf: directory.knownHosts, encoding: .utf8)
        check(known.hasPrefix("\(web.sshAlias) \(web.hostKeys[0])\n") && known.contains("\(db.sshAlias) \(db.hostKeys[0])"),
              "known_hosts under the dated aliases")
        check(GrantSSHConfig.argv(web, in: directory) == ["ssh", "-F", directory.sshConfig.path, web.sshAlias], "argv")

        try FileManager.default.removeItem(at: directory.sshConfig)
        let gone = try run("/usr/bin/ssh", ["-F", directory.sshConfig.path, web.sshAlias, "true"])
        check(gone.status == 255 && gone.stderr.contains("Can't open user config file"),
              "an old command fails once the config is gone, without falling back: \(gone.stderr)")

        var pty = request
        pty.permissions = AccessPermissions(forceCommand: "/bin/date", pty: true)
        check(!(try GrantSSHConfig.render(pty, in: directory)).contains("RequestTTY"), "PTY grants keep the default RequestTTY")
        var quoted = request
        quoted.targets[0].hostname = "bad host"
        check(throwsError { _ = try GrantSSHConfig.render(quoted, in: directory) }, "unsafe host names refused")
    }

    test("instructions for AI agents: the snippet matches the docs; --add-to asks, adds once and updates in place") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
        let snippet = try run(cliBinary, ["instructions", "--snippet"]).stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let docs = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("docs/ai-agents.md")
        let guide = (try? String(contentsOf: docs, encoding: .utf8)) ?? ""
        let block = guide.components(separatedBy: "## Copyable discovery block").last?
            .components(separatedBy: "```markdown\n").dropFirst().first?
            .components(separatedBy: "\n```").first ?? ""
        check(!snippet.isEmpty && snippet == block.trimmingCharacters(in: .whitespacesAndNewlines),
              "docs/ai-agents.md holds the same block the CLI prints")
        check(snippet.contains("touchid-ssh-agent instructions") && snippet.contains("access status --json")
              && snippet.contains("ssh_argv"), "the block points to the workflow")

        func addTo(_ file: URL, answer: String) throws -> ShellResult {
            try expectScript(#"""
            spawn $env(CLI) instructions --add-to $env(FILE)
            expect {
              "Write it?" { send -- "$env(ANSWER)\r"; exp_continue }
              eof
            }
            """#, paths: paths, extra: ["FILE": file.path, "ANSWER": answer], in: directory)
        }
        let file = directory.appendingPathComponent("CLAUDE.md")
        try "# My rules\nBe brief.".write(to: file, atomically: true, encoding: .utf8)
        let declined = try addTo(file, answer: "n")
        check(declined.stdout.contains("Nothing was changed"), "declined: \(declined.stdout.suffix(200))")
        check(try String(contentsOf: file, encoding: .utf8) == "# My rules\nBe brief.", "unchanged when declined")

        let added = try addTo(file, answer: "y")
        check(added.stdout.contains("Added the block"), "added: \(added.stdout.suffix(300))")
        let text = try String(contentsOf: file, encoding: .utf8)
        check(text.hasPrefix("# My rules\nBe brief.\n\n<!-- touchid-ssh-agent: begin"), "appended after the existing text")
        check(text.components(separatedBy: snippet).count == 2 && text.hasSuffix("<!-- touchid-ssh-agent: end -->\n"), "one block")

        let again = try addTo(file, answer: "y")
        check(again.stdout.contains("already has the current"), "second run: nothing to do")
        check(try String(contentsOf: file, encoding: .utf8) == text, "unchanged on the second run")

        // An older block (other text between the markers) is replaced in place.
        let older = text.replacingOccurrences(of: snippet, with: "old wording") + "\n## After\nkept\n"
        try older.write(to: file, atomically: true, encoding: .utf8)
        let updated = try addTo(file, answer: "y")
        check(updated.stdout.contains("will be replaced") && updated.stdout.contains("Updated the block"), "updated")
        let after = try String(contentsOf: file, encoding: .utf8)
        check(after == text + "\n## After\nkept\n", "updated in place, the rest kept byte for byte: \(after)")

        let target = directory.appendingPathComponent("real-AGENTS.md")
        let link = directory.appendingPathComponent("AGENTS.md")
        try "".write(to: target, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        _ = try addTo(link, answer: "y")
        check((try? FileManager.default.destinationOfSymbolicLink(atPath: link.path)) == target.path, "a linked file stays a link")
        check(try String(contentsOf: target, encoding: .utf8).contains(snippet), "the link's target got the block")

        let fresh = directory.appendingPathComponent("new/CLAUDE.md")
        let refused = try run(cliBinary, ["instructions", "--add-to", fresh.path])
        check(refused.status != 0 && refused.stderr.contains("--snippet"), "without a terminal it explains instead of writing")
        check(!FileManager.default.fileExists(atPath: fresh.path), "nothing created without confirmation")
        _ = try addTo(fresh, answer: "y")
        check(try String(contentsOf: fresh, encoding: .utf8).hasPrefix("<!-- touchid-ssh-agent: begin"), "a new file is created after yes")
        check(try run(cliBinary, ["instructions", "--bogus"]).status != 0, "unknown options refused")
    }

    test("socket path length is checked before approval") {
        let long = AgentPaths(directory: URL(fileURLWithPath: "/tmp/" + String(repeating: "d", count: 70)))
        check(throwsError { try GrantDirectory.checkSocketPathLength(paths: long) }, "too long")
        check(!throwsError { try GrantDirectory.checkSocketPathLength(paths: AgentPaths(directory: URL(fileURLWithPath: "/tmp/x"))) },
              "short is fine")
    }

    test("inventory: older files load; temporary-access fields round trip") {
        let legacy = """
        {
          "mac" : "touchid-ssh-agent@old",
          "servers" : [
            {
              "alias" : "web", "authorizedAt" : "2026-01-02T03:04:05Z", "destination" : "web",
              "hostname" : "server.example", "loginKeyFingerprint" : "SHA256:a", "port" : 22,
              "recoveryKeyFingerprint" : "SHA256:b", "user" : "deploy"
            }
          ],
          "updatedAt" : "2026-01-02T03:04:05Z",
          "version" : 1
        }
        """
        let old = try Inventory.decode(Data(legacy.utf8))
        check(old.servers.count == 1 && old.servers[0].temporaryAccess == nil, "legacy entry without temporary access")

        var inventory = old
        let ca = SoftwareCA()
        var enrollment = TemporaryAccessEnrollment(
            targetId: "0123456789abcdef", principal: "access-0123456789abcdef",
            caPublicKey: SSHKeyFormat.authorizedKeyLine(blob: ca.blob, comment: "ca@mac"), caFingerprint: ca.fingerprint,
            authorizedKeyOptions: CATrust.options(principal: "access-0123456789abcdef"), enrolledAt: Date(timeIntervalSince1970: 1_800_000_000),
            verified: true)
        enrollment.lastGrant = GrantSummary(grantId: "20261015-a1b2c3d4e5f6", serial: 3, temporaryKeyFingerprint: "SHA256:t",
                                            sshAlias: "web-access-20261015-a1b2c3d4e5f6", issuedAt: Date(timeIntervalSince1970: 1_800_000_000),
                                            expiresAt: Date(timeIntervalSince1970: 1_800_003_600), forceCommand: nil, pty: false)
        enrollment.caRotation = CARotation(recoveryId: "r1", oldCAPublicKey: enrollment.caPublicKey, oldCAFingerprint: ca.fingerprint,
                                           newCAPublicKey: "x", newCAFingerprint: "SHA256:new", principal: enrollment.principal,
                                           authorizedKeyOptions: enrollment.authorizedKeyOptions, step: .replacementAdded,
                                           updatedAt: Date(timeIntervalSince1970: 1_800_000_000))
        inventory.servers[0].temporaryAccess = enrollment
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
        try InventoryStore.save(inventory, to: paths)
        let loaded = try InventoryStore.load(from: paths)
        check(loaded == inventory, "round trip")
        check(loaded.servers[0].temporaryAccess?.caBlob == ca.blob && loaded.servers[0].temporaryAccess?.caRotation?.oldCABlob == ca.blob,
              "CA blobs only when the fingerprint matches")
        var damaged = enrollment
        damaged.caFingerprint = "SHA256:other"
        check(damaged.caBlob == nil, "a record whose key and fingerprint disagree yields no key to remove")
        let json = try String(contentsOf: paths.inventoryFile, encoding: .utf8)
        check(!json.contains("agent.sock") && !json.contains("PRIVATE"), "no live paths or private material")
    }

    test("inventory updates are serialized; serials are unique") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = AgentPaths(directory: directory.appendingPathComponent("a"))
        let group = DispatchGroup()
        let lock = NSLock()
        var serials: [UInt64] = []
        for index in 0..<24 {
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                try? InventoryStore.update(paths) { inventory in
                    inventory.upsert(InventoryEntry(alias: "s\(index)", destination: "s\(index)", hostname: "h\(index)", user: "u",
                                                    port: 22, sshConfigFile: nil, loginKeyFingerprint: "a",
                                                    recoveryKeyFingerprint: "b", authorizedAt: Date()))
                }
                if let serial = try? CertificateSerial.next(paths: paths) {
                    lock.lock(); serials.append(serial); lock.unlock()
                }
            }
        }
        group.wait()
        check(try InventoryStore.load(from: paths).servers.count == 24, "no update lost")
        check(Set(serials).count == 24 && serials.count == 24, "24 distinct serials")
        check((try? String(contentsOf: paths.caSerialFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) == "24",
              "counter persisted")
    }

    test("grant cleanup: only manifested, owned, expected files; symlinks and strangers are skipped") {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = AgentPaths(directory: root.appendingPathComponent("a"))
        try paths.ensureAccessDirectories()
        let outside = root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try "precious".write(to: outside.appendingPathComponent("ssh_config"), atomically: true, encoding: .utf8)

        func makeGrant(_ id: String, process: ProcessIdentity?, expiresIn: TimeInterval = 3600) throws -> GrantDirectory {
            let directory = GrantDirectory(paths: paths, grantId: id)
            try directory.create()
            let target = sampleTarget("web", grantId: id)
            let request = AccessRequest(grantId: id, dataDirectory: paths.directory.path, caFingerprint: "SHA256:x", targets: [target],
                                        permissions: AccessPermissions(), requestedAt: UInt64(Date().timeIntervalSince1970),
                                        duration: UInt64(max(1, expiresIn)))
            var manifest = GrantManifest(request: request, launchLabel: nil)
            manifest.process = process
            if expiresIn <= 0 { manifest.expiresAt = UInt64(Date().timeIntervalSince1970) - 10 }
            try manifest.write(to: directory)
            try request.encoded().write(to: directory.request)
            try "Host x\n".write(to: directory.sshConfig, atomically: true, encoding: .utf8)
            return directory
        }
        // A finished child gives a process identity that is no longer running.
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run()
        let childIdentity = ProcessIdentity.of(pid: child.processIdentifier)
        child.waitUntilExit()
        let dead = ProcessIdentity(pid: child.processIdentifier, startSeconds: childIdentity?.startSeconds ?? 1, startMicroseconds: 0)

        let stale = try makeGrant("20261015-000000000001", process: dead, expiresIn: 0)
        let live = try makeGrant("20261015-000000000002", process: ProcessIdentity.current())
        let reused = try makeGrant("20261015-000000000003",
                                   process: ProcessIdentity(pid: getpid(), startSeconds: 1, startMicroseconds: 1))
        let stranger = try makeGrant("20261015-000000000004", process: nil)
        try "mine".write(to: stranger.url.appendingPathComponent("notes.txt"), atomically: true, encoding: .utf8)
        let linked = try makeGrant("20261015-000000000005", process: nil)
        try FileManager.default.removeItem(at: linked.sshConfig)
        try FileManager.default.createSymbolicLink(at: linked.sshConfig, withDestinationURL: outside.appendingPathComponent("ssh_config"))
        try FileManager.default.createSymbolicLink(at: paths.grantsDirectory.appendingPathComponent("20261015-000000000006"),
                                                   withDestinationURL: outside)
        let wrongName = try makeGrant("20261015-000000000007", process: nil)
        guard var manifest = GrantManifest.read(from: wrongName) else { check(false, "manifest"); return }
        manifest.grantId = "20261015-000000000099"
        try manifest.write(to: wrongName)
        try FileManager.default.createDirectory(at: paths.grantsDirectory.appendingPathComponent("20261015-000000000008"),
                                                withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: paths.grantsDirectory.appendingPathComponent("not-a-grant"),
                                                withIntermediateDirectories: false)

        let inspections = Dictionary(uniqueKeysWithValues: GrantStore.inspectAll(paths: paths).map { ($0.grantId, $0) })
        check(inspections["20261015-000000000001"]?.problem == nil && inspections["20261015-000000000001"]?.running == false,
              "stale grant is owned and not running")
        check(inspections["20261015-000000000002"]?.running == true, "this process counts as running")
        check(inspections["20261015-000000000003"]?.running == false, "same pid with another start time is not the job")
        check(inspections["20261015-000000000004"]?.problem?.contains("unexpected file") == true, "unexpected file")
        check(inspections["20261015-000000000005"]?.problem != nil, "symlink inside")
        check(inspections["20261015-000000000006"]?.problem?.contains("not a real directory") == true, "symlinked grant directory")
        check(inspections["20261015-000000000007"]?.problem?.contains("manifest") == true, "manifest of another grant")
        check(inspections["20261015-000000000008"]?.empty == true, "empty directory")
        check(inspections["not-a-grant"]?.problem != nil, "foreign name")

        try GrantStore.remove(inspections["20261015-000000000001"]!, paths: paths)
        check(!FileManager.default.fileExists(atPath: stale.url.path), "stale grant removed")
        try GrantStore.remove(inspections["20261015-000000000008"]!, paths: paths)
        for (id, inspection) in inspections where inspection.problem != nil {
            check(throwsError { try GrantStore.remove(inspection, paths: paths) }, "\(id) refused")
        }
        check(FileManager.default.fileExists(atPath: live.url.path) && FileManager.default.fileExists(atPath: reused.url.path),
              "others untouched")
        check(try String(contentsOf: outside.appendingPathComponent("ssh_config"), encoding: .utf8) == "precious", "outside file intact")
        check(FileManager.default.fileExists(atPath: stranger.url.appendingPathComponent("notes.txt").path), "user file intact")
    }
}

func runAccessSecureEnclaveTests() {
    print("Temporary access: CA, in-memory agent and grant job")

    test("CA: separate Secure Enclave key, never on the login agent's socket") {
        let agent = try LiveAgent.start()
        defer { agent.stop() }
        check(throwsError { try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: AgentPaths(directory: AgentPaths.defaultDirectory)) },
              "test CA never in the default directory")
        let ca = try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: agent.paths)
        check(ca.publicKeyBlob != agent.identity.publicKeyBlob, "a different key from the login key")
        check(throwsError { try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: agent.paths) }, "never replaced")
        check(try CertificateAuthorityStore.load(from: agent.paths)?.publicKeyBlob == ca.publicKeyBlob, "reloads")
        check(try IdentityStore.load(from: agent.paths)?.publicKeyBlob == agent.identity.publicKeyBlob, "login key files untouched")
        let listed = try run("/usr/bin/ssh-add", ["-L"], environment: agent.environment).stdout
        check(!listed.contains(ca.publicKeyBlob.base64EncodedString()), "the CA is not offered by agent.sock")
        check(listed.trimmingCharacters(in: .whitespacesAndNewlines) == agent.identity.authorizedKeyLine, "only the login key")
        let mode = (try? FileManager.default.attributesOfItem(atPath: agent.paths.caKeyFile.path))?[.posixPermissions] as? Int
        check(mode == 0o600, "ca.se 0600")
        // The Secure Enclave CA signs a certificate ssh-keygen accepts.
        let issued = try CertificateIssuer.issue(ca: ca.publicKeyBlob, serial: try CertificateSerial.next(paths: agent.paths),
                                                keyID: "access-se", principals: ["access-a"], validAfter: 1, validBefore: 4_000_000_000) {
            try SecureEnclaveSigner.sign($0, with: ca, reason: "test")
        }
        let file = try writeCertificate(issued.blob, in: agent.directory)
        let out = try run("/usr/bin/ssh-keygen", ["-Lf", file.path])
        check(out.status == 0 && out.stdout.contains("Signing CA: ECDSA \(ca.fingerprint)"), "SE-signed certificate: \(out.stdout)")
    }

    test("temporary agent: key and certificate only, plain Ed25519 signatures for allowed logins") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ca = SoftwareCA()
        let issued = try CertificateIssuer.issue(ca: ca.blob, serial: 5, keyID: "access-t", principals: ["access-a"], validAfter: 1,
                                                validBefore: 4_000_000_000, sign: ca.sign)
        let clock = ManualClock()
        let socket = directory.appendingPathComponent("agent.sock").path
        let agent = TemporaryAgent(socketPath: socket, credential: issued,
                                   deadline: GrantDeadline(expiresAt: clock.wall + 60, clock: clock),
                                   allowedUsers: ["deploy"], comment: "grant", log: nil, logName: "t")
        try agent.start()
        defer { agent.stop() }
        let mode = (try? FileManager.default.attributesOfItem(atPath: socket))?[.posixPermissions] as? Int
        check(mode == 0o600, "socket 0600")
        let listed = try run("/usr/bin/ssh-add", ["-L"], environment: ["SSH_AUTH_SOCK": socket]).stdout
        let lines = listed.split(separator: "\n")
        check(lines.count == 2 && lines[0].hasPrefix(SSHCertificate.type) && lines[1].hasPrefix("ssh-ed25519 "), "cert and key: \(listed)")
        check(!listed.contains(ca.blob.base64EncodedString()), "no CA")

        for blob in [issued.blob, issued.publicKeyBlob] {
            let payload = userAuthPayload(user: "deploy", offering: blob)
            let response = AgentClient.roundTrip(socketPath: socket, body: signRequest(blob, payload)) ?? Data()
            var reader = SSHReader(response)
            check((try? reader.readByte()) == AgentMessage.signResponse, "signed for \(SSHKeyFormat.keyTypeName(ofBlob: blob) ?? "?")")
            let signature = (try? reader.readString()) ?? Data()
            check(SSHKeyFormat.keyTypeName(ofBlob: signature) == "ssh-ed25519", "a plain ssh-ed25519 signature blob")
            let raw = (try? Ed25519SSH.rawSignature(fromBlob: signature)) ?? Data()
            check(issued.privateKey.publicKey.isValidSignature(raw, for: payload), "verifies with the temporary key")
        }
        let hostbound = userAuthPayload(user: "deploy", offering: issued.blob, hostKey: Data([1, 2, 3]))
        check(AgentClient.roundTrip(socketPath: socket, body: signRequest(issued.blob, hostbound))?.first == AgentMessage.signResponse,
              "publickey-hostbound logins are signed")
        var sshsig = SSHWriter()
        sshsig.writeString("git")
        let refused: [(Data, Data, String)] = [
            (issued.blob, Data("SSHSIG".utf8) + sshsig.data, "git signature"),
            (issued.blob, userAuthPayload(user: "root", offering: issued.blob), "another account"),
            (issued.blob, userAuthPayload(user: "deploy", offering: ca.blob), "payload for another key"),
            (ca.blob, userAuthPayload(user: "deploy", offering: ca.blob), "the CA blob"),
            (issued.blob, Data("arbitrary".utf8), "arbitrary data"),
        ]
        for (blob, payload, label) in refused {
            check(AgentClient.roundTrip(socketPath: socket, body: signRequest(blob, payload)) == AgentProtocol.failure, "refused: \(label)")
        }
        check(AgentClient.roundTrip(socketPath: socket, body: Data([17])) == AgentProtocol.failure, "add identity refused")
        check(agent.signatureCount == 3, "three signatures: \(agent.signatureCount)")
    }

    test("temporary agent: the deadline holds for connected clients and against clock changes") {
        let directory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ca = SoftwareCA()
        let issued = try CertificateIssuer.issue(ca: ca.blob, serial: 6, keyID: "access-t", principals: ["access-a"], validAfter: 1,
                                                validBefore: 4_000_000_000, sign: ca.sign)
        let payload = userAuthPayload(user: "deploy", offering: issued.blob)
        func agent(_ clock: ManualClock, _ name: String) throws -> (TemporaryAgent, String) {
            let socket = directory.appendingPathComponent("\(name).sock").path
            let agent = TemporaryAgent(socketPath: socket, credential: issued, deadline: GrantDeadline(expiresAt: clock.wall + 60, clock: clock),
                                       allowedUsers: ["deploy"], comment: "grant", log: nil, logName: name)
            try agent.start()
            return (agent, socket)
        }
        func signOn(_ fd: Int32) -> UInt8? {
            guard SocketIOForTests.write(fd, AgentProtocol.frame(signRequest(issued.blob, payload))) else { return nil }
            return SocketIOForTests.read(fd)?.first
        }

        let clock = ManualClock()
        let (held, socket) = try agent(clock, "held")
        defer { held.stop() }
        guard let fd = AgentClient.connect(socketPath: socket) else { check(false, "connect"); return }
        defer { close(fd) }
        check(signOn(fd) == AgentMessage.signResponse, "signs before the deadline")
        clock.wall += 61
        clock.monotonic += 61
        check(signOn(fd) == AgentMessage.failure, "the same open connection is refused after the deadline")
        check(AgentClient.listIdentities(socketPath: socket)?.isEmpty == true, "no identities after expiry")

        let backwards = ManualClock()
        let (rewound, rewoundSocket) = try agent(backwards, "rewound")
        defer { rewound.stop() }
        backwards.wall -= 3600   // someone sets the clock back an hour
        backwards.monotonic += 61
        check(AgentClient.roundTrip(socketPath: rewoundSocket, body: signRequest(issued.blob, payload)) == AgentProtocol.failure,
              "setting the wall clock back does not extend the grant")

        let forwards = ManualClock()
        let (jumped, jumpedSocket) = try agent(forwards, "jumped")
        defer { jumped.stop() }
        forwards.wall += 3600
        check(AgentClient.roundTrip(socketPath: jumpedSocket, body: signRequest(issued.blob, payload)) == AgentProtocol.failure,
              "a wall clock past the deadline ends it even if little time passed")

        let open = ManualClock()
        let (stopping, stoppingSocket) = try agent(open, "stopping")
        guard let client = AgentClient.connect(socketPath: stoppingSocket) else { check(false, "connect"); return }
        defer { close(client) }
        stopping.stop()
        var byte: UInt8 = 0
        check(read(client, &byte, 1) == 0, "stop closes connected clients")
        check(!FileManager.default.fileExists(atPath: stoppingSocket), "stop removes the socket")
    }

    test("grant job: denial, abandoned start and a vanished caller publish nothing") {
        let fixture = try JobFixture.make()
        defer { fixture.remove() }

        let denied = try fixture.prepare()
        let deniedJob = AccessJob(paths: fixture.paths, grantDirectory: denied.directory.url, digest: denied.digest,
                                  signer: { _, _, _, _ in throw SignError.canceled }, options: fixture.options())
        let deniedRun = fixture.start(deniedJob)
        let owner = ControlConnection.connect(denied.directory.controlSocket.path, timeout: 5)
        check(owner?.request(["op": "attach"], timeout: 5)?["event"] as? String == "attached", "attached")
        var events: [String] = []
        while let message = owner?.receive(timeout: 5), let event = message["event"] as? String {
            events.append(event)
            if event == "failed" { check(message["code"] as? String == "approval_denied", "code: \(message)") }
        }
        check(events == ["approval-requested", "failed"], "events: \(events)")
        check(deniedRun.wait() == 1, "job exits with failure")
        check(!FileManager.default.fileExists(atPath: denied.directory.url.path), "nothing left after denial")

        let timedOut = try fixture.prepare()
        let timeoutJob = AccessJob(paths: fixture.paths, grantDirectory: timedOut.directory.url, digest: timedOut.digest,
                                   signer: { _, _, _, _ in throw SignError.timedOut }, options: fixture.options())
        let timeoutRun = fixture.start(timeoutJob)
        let timeoutOwner = ControlConnection.connect(timedOut.directory.controlSocket.path, timeout: 5)
        _ = timeoutOwner?.request(["op": "attach"], timeout: 5)
        var timeoutCode: String?
        while let message = timeoutOwner?.receive(timeout: 5) {
            if message["event"] as? String == "failed" { timeoutCode = message["code"] as? String }
        }
        check(timeoutCode == "approval_timeout", "timeout code: \(timeoutCode ?? "-")")
        check(timeoutRun.wait() == 1 && !FileManager.default.fileExists(atPath: timedOut.directory.url.path), "timeout cleaned")

        let abandoned = try fixture.prepare()
        var options = fixture.options()
        options.attachTimeout = 1
        let abandonedRun = fixture.start(AccessJob(paths: fixture.paths, grantDirectory: abandoned.directory.url,
                                                   digest: abandoned.digest, options: options))
        check(abandonedRun.wait() == 3, "nobody attached")
        check(!FileManager.default.fileExists(atPath: abandoned.directory.url.path), "abandoned start cleaned")

        // The caller disappears while the prompt is up: the prompt is withdrawn.
        let pending = try fixture.prepare()
        let promptShown = DispatchSemaphore(value: 0)
        let pendingJob = AccessJob(paths: fixture.paths, grantDirectory: pending.directory.url, digest: pending.digest,
                                   signer: { _, _, _, cancellation in
                                       promptShown.signal()
                                       while !cancellation.isCancelled { usleep(20_000) }
                                       throw SignError.timedOut
                                   }, options: fixture.options())
        let pendingRun = fixture.start(pendingJob)
        let caller = ControlConnection.connect(pending.directory.controlSocket.path, timeout: 5)
        _ = caller?.request(["op": "attach"], timeout: 5)
        check(promptShown.wait(timeout: .now() + 5) == .success, "prompt reached")
        caller?.close()
        check(pendingRun.wait() == 1, "job ends when its caller goes away")
        check(!FileManager.default.fileExists(atPath: pending.directory.url.path), "nothing published")

        // A bad digest (the request changed after the summary) is refused.
        let tampered = try fixture.prepare()
        let tamperedRun = fixture.start(AccessJob(paths: fixture.paths, grantDirectory: tampered.directory.url,
                                                  digest: String(repeating: "0", count: 64), options: fixture.options()))
        check(tamperedRun.wait() == 1, "digest mismatch refused")
        check(!FileManager.default.fileExists(atPath: tampered.directory.url.path), "and cleaned")
    }

    test("grant job: issues after approval, publishes only then, ends on abort, stop and expiry") {
        let fixture = try JobFixture.make()
        defer { fixture.remove() }

        // Abort after issuance (readiness failed): everything disappears.
        let aborted = try fixture.prepare()
        let abortedRun = fixture.start(AccessJob(paths: fixture.paths, grantDirectory: aborted.directory.url, digest: aborted.digest,
                                                 options: fixture.options()))
        let owner = ControlConnection.connect(aborted.directory.controlSocket.path, timeout: 5)
        _ = owner?.request(["op": "attach"], timeout: 5)
        check(!FileManager.default.fileExists(atPath: aborted.directory.agentSocket.path), "no agent socket before approval")
        var issued: [String: Any]?
        while let message = owner?.receive(timeout: 10) {
            if message["event"] as? String == "issued" { issued = message; break }
        }
        check(issued != nil, "issued")
        for file in [aborted.directory.publicKey, aborted.directory.certificate, aborted.directory.sshConfig,
                     aborted.directory.knownHosts, aborted.directory.agentSocket] {
            check(FileManager.default.fileExists(atPath: file.path), "published \(file.lastPathComponent)")
        }
        let entries = (try? FileManager.default.contentsOfDirectory(at: aborted.directory.url, includingPropertiesForKeys: nil)) ?? []
        for entry in entries where !entry.lastPathComponent.hasSuffix(".sock") {
            let text = (try? String(contentsOf: entry, encoding: .utf8)) ?? ""
            check(!text.contains("PRIVATE KEY"), "no private key in \(entry.lastPathComponent)")
        }
        let certificate = try run("/usr/bin/ssh-keygen", ["-Lf", aborted.directory.certificate.path]).stdout
        check(certificate.contains("access-web") && certificate.contains("access-db"), "one certificate, both principals")
        check(GrantManifest.read(from: aborted.directory)?.process == ProcessIdentity.current(),
              "manifest records the job's process identity")
        owner?.send(["op": "abort", "reason": "readiness-failed"])
        check(abortedRun.wait() == 1, "abort ends the job")
        check(!FileManager.default.fileExists(atPath: aborted.directory.url.path), "aborted grant removed")

        // Confirmed, then stopped through the control socket.
        let stopped = try fixture.prepare()
        let stoppedRun = fixture.start(AccessJob(paths: fixture.paths, grantDirectory: stopped.directory.url, digest: stopped.digest,
                                                 options: fixture.options()))
        let stoppedOwner = ControlConnection.connect(stopped.directory.controlSocket.path, timeout: 5)
        _ = stoppedOwner?.request(["op": "attach"], timeout: 5)
        while let message = stoppedOwner?.receive(timeout: 10), message["event"] as? String != "issued" {}
        stoppedOwner?.send(["op": "confirm"])
        check(stoppedOwner?.receive(timeout: 5)?["event"] as? String == "active", "active after confirmation")
        stoppedOwner?.close()
        usleep(200_000)
        check(AccessControl.request(stopped.directory, ["op": "status"])?["state"] as? String == "active", "status: active")
        let summary = try InventoryStore.load(from: fixture.paths).servers.first?.temporaryAccess?.lastGrant
        check(summary?.grantId == stopped.directory.grantId && summary?.endedAt == nil, "inventory records the grant")
        check(AccessControl.request(stopped.directory, ["op": "stop"])?["event"] as? String == "stopping", "stop accepted")
        check(stoppedRun.wait() == 0, "stopped cleanly")
        check(!FileManager.default.fileExists(atPath: stopped.directory.url.path), "stopped grant removed")
        let ended = try InventoryStore.load(from: fixture.paths).servers.first?.temporaryAccess?.lastGrant
        check(ended?.endReason == "stopped" && ended?.endedAt != nil, "end recorded: \(String(describing: ended))")

        // Expiry by the (injected) clock while a client stays connected.
        let clock = ManualClock()
        var options = fixture.options()
        options.clock = clock
        options.checkInterval = 0.2
        let expiring = try fixture.prepare(duration: 120, requestedAt: UInt64(clock.wall))
        let expiringRun = fixture.start(AccessJob(paths: fixture.paths, grantDirectory: expiring.directory.url,
                                                  digest: expiring.digest, options: options))
        let expiringOwner = ControlConnection.connect(expiring.directory.controlSocket.path, timeout: 5)
        _ = expiringOwner?.request(["op": "attach"], timeout: 5)
        while let message = expiringOwner?.receive(timeout: 10), message["event"] as? String != "issued" {}
        expiringOwner?.send(["op": "confirm"])
        _ = expiringOwner?.receive(timeout: 5)
        let held = AgentClient.connect(socketPath: expiring.directory.agentSocket.path)
        clock.wall += 121
        clock.monotonic += 121
        check(expiringRun.wait() == 0, "job ends at the deadline")
        check(!FileManager.default.fileExists(atPath: expiring.directory.url.path), "expired grant removed")
        if let held {
            var byte: UInt8 = 0
            check(read(held, &byte, 1) <= 0, "the held agent connection was closed")
            close(held)
        }
        let expired = try InventoryStore.load(from: fixture.paths).servers.first?.temporaryAccess?.lastGrant
        check(expired?.endReason == "expired", "end reason expired: \(String(describing: expired?.endReason))")
    }
}

/// Raw framed I/O for tests that keep one agent connection open.
enum SocketIOForTests {
    static func write(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, data.count) } == data.count
    }

    static func read(_ fd: Int32) -> Data? {
        var header = [UInt8](repeating: 0, count: 4)
        guard Darwin.read(fd, &header, 4) == 4 else { return nil }
        let length = header.reduce(0) { $0 << 8 | Int($1) }
        var body = [UInt8](repeating: 0, count: length)
        var received = 0
        while received < length {
            let count = body.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress! + received, length - received) }
            guard count > 0 else { return nil }
            received += count
        }
        return Data(body)
    }
}

/// A data directory with a test CA and an enrolled two-server inventory, where
/// grant jobs run on a background thread of this process.
struct JobFixture {
    let root: URL
    let paths: AgentPaths
    let ca: StoredIdentity

    static func make() throws -> JobFixture {
        let root = try makeShortTempDirectory()
        let paths = AgentPaths(directory: root.appendingPathComponent("a"))
        let ca = try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: paths)
        try paths.ensureAccessDirectories()
        var inventory = Inventory(mac: "test")
        for name in ["web", "db"] {
            var entry = InventoryEntry(alias: name, destination: name, hostname: "\(name).example", user: "deploy", port: 22,
                                       sshConfigFile: nil, loginKeyFingerprint: "a", recoveryKeyFingerprint: "b", authorizedAt: Date())
            entry.temporaryAccess = TemporaryAccessEnrollment(
                targetId: "id-\(name)", principal: "access-\(name)", caPublicKey: ca.authorizedKeyLine, caFingerprint: ca.fingerprint,
                authorizedKeyOptions: CATrust.options(principal: "access-\(name)"), enrolledAt: Date(), verified: true)
            inventory.upsert(entry)
        }
        try InventoryStore.save(inventory, to: paths)
        return JobFixture(root: root, paths: paths, ca: ca)
    }

    func options() -> AccessJob.Options {
        var options = AccessJob.Options()
        options.attachTimeout = 5
        options.confirmTimeout = 10
        options.preventsIdleSleep = false
        options.observesWake = false
        return options
    }

    func prepare(duration: UInt64 = 300, requestedAt: UInt64 = UInt64(Date().timeIntervalSince1970))
        throws -> (directory: GrantDirectory, digest: String) {
        let grantId = AccessNames.newGrantId()
        let directory = GrantDirectory(paths: paths, grantId: grantId)
        try directory.create()
        var targets = [sampleTarget("web", grantId: grantId, principal: "access-web"),
                       sampleTarget("db", grantId: grantId, principal: "access-db")]
        targets[0].targetId = "id-web"
        targets[1].targetId = "id-db"
        let request = AccessRequest(grantId: grantId, dataDirectory: paths.directory.path, caFingerprint: ca.fingerprint,
                                    targets: targets, permissions: AccessPermissions(), requestedAt: requestedAt, duration: duration)
        let data = try request.encoded()
        try SecureFile.writeAtomically(data, to: directory.request, mode: 0o600)
        try GrantManifest(request: request, launchLabel: nil).write(to: directory)
        return (directory, AccessRequest.digest(data))
    }

    final class Running {
        let done = DispatchSemaphore(value: 0)
        var status: Int32 = -1
        func wait() -> Int32 {
            guard done.wait(timeout: .now() + 30) == .success else { return -99 }
            return status
        }
    }

    func start(_ job: AccessJob) -> Running {
        let running = Running()
        Thread {
            running.status = job.run()
            running.done.signal()
        }.start()
        return running
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}

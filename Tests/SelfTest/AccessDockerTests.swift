// Temporary access against real sshd containers: enrollment, grants, expiry,
// stop, crash, cleanup, audit and deauthorize, all through the CLI binary.
// Grant jobs run as detached processes (TOUCHID_SSH_AGENT_ACCESS_LAUNCH=process)
// except in the launchd test; every key and CA is a test key in /tmp.

import CryptoKit
import Darwin
import Foundation
@_spi(Testing) import TouchIDSSHCore

struct DockerServer {
    let container: String
    let port: String
}

/// Shared state of the Docker temporary-access tests.
final class AccessE2E {
    let docker: String
    let image: String
    let work: URL
    let agent: LiveAgent
    let ca: StoredIdentity
    let kit: (kit: URL, publicKey: URL)
    let bootstrap: URL
    let bootstrapLine: String
    let config: URL
    let knownHosts: URL
    var servers: [String: DockerServer] = [:]

    init(docker: String, image: String) throws {
        self.docker = docker
        self.image = image
        work = try makeShortTempDirectory()
        agent = try LiveAgent.start(shortPath: true)
        ca = try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: agent.paths)
        kit = try plainKit(in: work, name: "emergency")
        try RecoveryStore.importPublicKey(from: kit.publicKey, into: agent.paths, replace: false)
        bootstrap = work.appendingPathComponent("bootstrap")
        try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "bootstrap", "-f", bootstrap.path])
        bootstrapLine = try String(contentsOf: bootstrap.appendingPathExtension("pub"), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        config = work.appendingPathComponent("ssh_config")
        knownHosts = work.appendingPathComponent("known_hosts")
        try SettingsStore.save(AgentSettings(backupPath: work.appendingPathComponent("cloud").path), to: agent.paths)
        try FileManager.default.createDirectory(at: work.appendingPathComponent("cloud"), withIntermediateDirectories: true)
    }

    var paths: AgentPaths { agent.paths }

    func stop() {
        for server in servers.values { _ = try? run(docker, ["rm", "-f", server.container]) }
        agent.stop()
        try? FileManager.default.removeItem(at: work)
    }

    @discardableResult
    func startServer(_ name: String, extra: String? = nil) throws -> DockerServer {
        var arguments = ["run", "-d", "--rm", "-p", "127.0.0.1::22", "-e", "AUTHORIZED_KEYS=\(bootstrapLine)"]
        if let extra { arguments += ["-e", "SSHD_EXTRA=\(extra)"] }
        let started = try run(docker, arguments + [image])
        guard started.status == 0 else { throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: started.stderr]) }
        let container = started.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let port = try run(docker, ["port", container, "22/tcp"]).stdout
            .split(separator: "\n").first?.split(separator: ":").last.map(String.init) ?? ""
        for _ in 0..<50 {
            if (try? run("/usr/bin/nc", ["-z", "127.0.0.1", port]))?.status == 0 { break }
            usleep(100_000)
        }
        usleep(500_000)
        servers[name] = DockerServer(container: container, port: port)
        try writeConfig()
        return servers[name]!
    }

    /// `Host e2e-NAME` blocks that reach each server with the bootstrap key.
    func writeConfig() throws {
        let blocks = servers.keys.sorted().map { name -> String in
            """
            Host e2e-\(name)
              HostName 127.0.0.1
              Port \(servers[name]!.port)
              User tester
              IdentityFile \(bootstrap.path)
              IdentitiesOnly yes
              IdentityAgent none
              StrictHostKeyChecking no
              UserKnownHostsFile \(knownHosts.path)
              LogLevel ERROR
            """
        }
        try (blocks.joined(separator: "\n\n") + "\n").write(to: config, atomically: true, encoding: .utf8)
    }

    func authorizedKeys(_ name: String) throws -> String {
        try run(docker, ["exec", servers[name]!.container, "cat", "/home/tester/.ssh/authorized_keys"]).stdout
    }

    /// Runs a shell snippet on the server as the test account.
    @discardableResult
    func onServer(_ name: String, _ script: String) throws -> ShellResult {
        try run(docker, ["exec", "-u", "tester", servers[name]!.container, "sh", "-c", script])
    }

    var environment: [String: String] {
        [AgentPaths.environmentVariable: paths.directory.path, AccessLauncher.modeVariable: "process",
         "TOUCHID_SSH_AGENT_NO_REVEAL": "1"]
    }

    func cli(_ arguments: [String], launchd: Bool = false) throws -> ShellResult {
        var environment = self.environment
        if launchd { environment[AccessLauncher.modeVariable] = "launchd" }
        return try run(cliBinary, arguments, environment: environment)
    }

    /// The single JSON document on stdout, or nil when stdout is anything else.
    func json(_ result: ShellResult) -> [String: Any]? {
        guard let data = result.stdout.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return object
    }

    func errorCode(_ result: ShellResult) -> String? {
        (json(result)?["error"] as? [String: Any])?["code"] as? String
    }

    var grantDirectories: [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: paths.grantsDirectory.path)) ?? []).sorted()
    }

    func entry(_ alias: String) throws -> InventoryEntry? {
        try InventoryStore.load(from: paths).servers.first { $0.alias == alias }
    }

    /// Runs a returned argv plus a remote command, without a shell.
    func ssh(_ argv: [String], _ extra: [String] = [], command: [String] = []) throws -> ShellResult {
        guard argv.count == 4, argv[0] == "ssh" else { return ShellResult(status: -1, stdout: "", stderr: "bad argv") }
        return try run("/usr/bin/ssh", Array(argv.dropFirst().prefix(2)) + extra + [argv[3]] + command)
    }

    func argv(_ document: [String: Any]?, _ index: Int = 0) -> [String] {
        ((document?["targets"] as? [[String: Any]])?[safe: index]?["ssh_argv"] as? [String]) ?? []
    }

    func jobProcess(_ grantId: String) -> ProcessIdentity? {
        GrantManifest.read(from: GrantDirectory(paths: paths, grantId: grantId))?.process
    }

    func waitUntil(_ seconds: Double, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if condition() { return true }
            usleep(200_000)
        }
        return condition()
    }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}

func runAccessDockerTests(docker: String, image: String) {
    print("Temporary access against sshd containers (Docker)")
    let e2e: AccessE2E
    do {
        e2e = try AccessE2E(docker: docker, image: image)
    } catch {
        test("temporary access setup") { throw error }
        return
    }
    defer { e2e.stop() }
    let personalConfig = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
    let personalBefore = try? Data(contentsOf: personalConfig)

    test("authorize --temporary-access: one scoped CA line per server, distinct principals, inventory and backup") {
        for name in ["a", "b", "c"] { try e2e.startServer(name) }
        for name in ["a", "b", "c"] {
            let result = try e2e.cli(["authorize", "e2e-\(name)", "-F", e2e.config.path, "--alias", "srv-\(name)", "--temporary-access"])
            let problems = result.stdout.split(separator: "\n").filter { $0.contains("✗") || $0.contains("error") }
            check(result.status == 0, "authorize \(name): \(problems) \(result.stderr)")
            check(result.stdout.contains("accepted a certificate from this Mac's CA"), "certificate login checked on \(name)")
        }
        var principals = Set<String>()
        for name in ["a", "b", "c"] {
            let lines = try e2e.authorizedKeys(name).split(separator: "\n").map(String.init)
            let caLines = lines.filter { $0.contains(e2e.ca.publicKeyBlob.base64EncodedString()) }
            check(caLines.count == 1, "\(name): exactly one CA line")
            let entry = try e2e.entry("srv-\(name)")
            let enrollment = entry?.temporaryAccess
            check(enrollment?.verified == true && enrollment?.caFingerprint == e2e.ca.fingerprint, "\(name): enrollment recorded")
            if let enrollment {
                principals.insert(enrollment.principal)
                check(caLines.first?.hasPrefix(CATrust.options(principal: enrollment.principal) + " ") == true,
                      "\(name): exact scope: \(caLines.first ?? "-")")
                check(enrollment.authorizedKeyOptions == CATrust.options(principal: enrollment.principal), "\(name): options recorded")
            }
            check(lines.first == e2e.bootstrapLine, "\(name): existing key untouched")
            check(entry?.hostKeys?.isEmpty == false, "\(name): host keys recorded")
        }
        check(principals.count == 3, "a different principal for each server: \(principals)")
        let backup = e2e.work.appendingPathComponent("cloud").appendingPathComponent(InventoryBackup.fileName)
        let decrypted = try run(agePath ?? "age", ["-d", "-i", e2e.kit.kit.path, backup.path])
        check(decrypted.stdout.contains("temporaryAccess") && principals.allSatisfy(decrypted.stdout.contains),
              "the encrypted backup holds the CA trust")
        let listed = try run("/usr/bin/ssh-add", ["-L"], environment: e2e.agent.environment).stdout
        check(!listed.contains(e2e.ca.publicKeyBlob.base64EncodedString()), "agent.sock never offers the CA")

        // Running it again changes nothing; a plain authorize keeps the record.
        let principal = try e2e.entry("srv-a")?.temporaryAccess?.principal
        let again = try e2e.cli(["authorize", "e2e-a", "-F", e2e.config.path, "--alias", "srv-a", "--temporary-access"])
        check(again.status == 0 && again.stdout.contains("CA trust     : already there"), "idempotent: \(again.stdout.suffix(300))")
        check(try e2e.authorizedKeys("a").components(separatedBy: e2e.ca.publicKeyBlob.base64EncodedString()).count == 2, "no duplicate")
        check(try e2e.entry("srv-a")?.temporaryAccess?.principal == principal, "same principal")
        let plain = try e2e.cli(["authorize", "e2e-a", "-F", e2e.config.path, "--alias", "srv-a"])
        check(try plain.status == 0 && e2e.entry("srv-a")?.temporaryAccess?.principal == principal,
              "authorize without the option keeps the enrollment")
    }

    test("access: unknown, unenrolled, ambiguous and malformed requests fail before Touch ID, as JSON") {
        try InventoryStore.update(e2e.paths) { inventory in
            inventory.upsert(InventoryEntry(alias: "plain", destination: "plain", hostname: "203.0.113.9", user: "tester", port: 22,
                                            sshConfigFile: nil, loginKeyFingerprint: "x", recoveryKeyFingerprint: "y",
                                            authorizedAt: Date(), hostKeys: ["ssh-ed25519 AAAA"]))
        }
        let cases: [([String], String, Int32)] = [
            (["access", "nope", "--for", "1h", "--json"], "unknown_target", 1),
            (["access", "srv-a,plain", "--for", "1h", "--json"], "not_enrolled", 1),
            (["access", "tester@127.0.0.1", "--for", "1h", "--json"], "ambiguous_target", 1),
            (["access", "srv-a, ,srv-b", "--for", "1h", "--json"], "invalid_arguments", 2),
            (["access", "srv-a,--all", "--for", "1h", "--json"], "invalid_arguments", 2),
            (["access", "srv-a", "--json"], "invalid_duration", 2),
            (["access", "srv-a", "--for", "13h", "--json"], "invalid_duration", 2),
            (["access", "srv-a", "--for", "0m", "--json"], "invalid_duration", 2),
            (["access", "srv-a", "--for", "1h", "--forward-agent", "--json"], "invalid_arguments", 2),
            (["access", "srv-a", "--for", "1h", "--for", "2h", "--json"], "invalid_arguments", 2),
            (["access", "status", "--for", "1h", "--json"], "invalid_arguments", 2),
            (["access", "srv-a", "srv-b", "--for", "1h", "--json"], "invalid_arguments", 2),
        ]
        for (arguments, code, status) in cases {
            let result = try e2e.cli(arguments)
            let document = e2e.json(result)
            check(document != nil, "\(arguments.joined(separator: " ")): stdout is one JSON document: \(result.stdout)")
            check(document?["ok"] as? Bool == false && document?["status"] as? String == "error"
                  && document?["schema_version"] as? Int == 1, "error envelope")
            check(e2e.errorCode(result) == code && result.status == status,
                  "\(arguments.joined(separator: " ")) → \(e2e.errorCode(result) ?? "-") / \(result.status)")
            check(result.stderr.contains("error:"), "a human message on stderr")
        }
        check(e2e.grantDirectories.isEmpty, "no grant directory was created: \(e2e.grantDirectories)")
        try InventoryStore.update(e2e.paths) { $0.servers.removeAll { $0.alias == "plain" } }
        let help = try e2e.cli(["access", "--help"])
        check(help.status == 0 && help.stdout.contains("--temporary-access") && help.stdout.contains("ssh_config")
              && help.stdout.contains("access cleanup"), "access --help")
        check(try e2e.cli(["access", "help"]).stdout == help.stdout, "access help is the same text")
    }

    var grant: [String: Any]?
    test("access: one approval for two targets, repeated commands through the returned argv, no fallback") {
        // "e2e-a" names srv-a again (its ssh alias): duplicates collapse to one target.
        let result = try e2e.cli(["access", "srv-a, srv-b,e2e-a", "--for", "3m", "--json"])
        grant = e2e.json(result)
        check(result.status == 0 && grant?["ok"] as? Bool == true && grant?["status"] as? String == "active",
              "granted: \(result.stdout) \(result.stderr.suffix(800))")
        check(result.stderr.contains("Targets (2)") && result.stderr.contains("Forwarding: none"), "summary on stderr")
        guard let grant, let grantId = grant["grant_id"] as? String else { return }
        let targets = grant["targets"] as? [[String: Any]] ?? []
        check(targets.map { $0["inventory_alias"] as? String } == ["srv-a", "srv-b"], "both targets")
        check(targets.allSatisfy { ($0["ssh_alias"] as? String)?.hasSuffix("-access-\(grantId)") == true }, "dated aliases")
        check((grant["remaining_seconds"] as? Int ?? 0) > 150 && (grant["expires_at"] as? String)?.hasSuffix("Z") == true, "expiry")
        check((grant["permissions"] as? [String: Any])?["pty"] as? Bool == false, "no PTY by default")
        for round in 0..<3 {
            for index in 0..<2 {
                let output = try e2e.ssh(e2e.argv(grant, index), command: ["echo", "round-\(round)-$(whoami)"])
                check(output.status == 0 && output.stdout.contains("round-\(round)-tester"), "argv \(index) round \(round): \(output.stderr)")
            }
        }
        let log = (try? String(contentsOf: e2e.paths.accessLogFile, encoding: .utf8)) ?? ""
        check(log.components(separatedBy: "issued grant=\(grantId)").count == 2, "one CA signature for the grant")
        check(log.components(separatedBy: "signed grant=\(grantId)").count >= 9, "temporary-key signatures for every login")
        check(!log.contains("127.0.0.1") && !log.contains("tester") && !log.contains("srv-a"), "log names no host or account")

        let directory = GrantDirectory(paths: e2e.paths, grantId: grantId)
        let mode = { (url: URL) in (try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int }
        check(mode(directory.url) == 0o700 && mode(directory.agentSocket) == 0o600, "0700 directory, 0600 socket")
        let offered = try run("/usr/bin/ssh-add", ["-L"], environment: ["SSH_AUTH_SOCK": directory.agentSocket.path]).stdout
        check(offered.split(separator: "\n").count == 2 && !offered.contains(e2e.ca.publicKeyBlob.base64EncodedString()),
              "grant socket: key and certificate, never the CA")
        for name in (try? FileManager.default.contentsOfDirectory(atPath: directory.url.path)) ?? [] where !name.hasSuffix(".sock") {
            let text = (try? String(contentsOf: directory.url.appendingPathComponent(name), encoding: .utf8)) ?? ""
            check(!text.contains("PRIVATE KEY"), "no private key in \(name)")
        }

        let argv = e2e.argv(grant)
        let unselected = try e2e.ssh(argv, ["-o", "Port=\(e2e.servers["c"]!.port)"], command: ["true"])
        check(unselected.status != 0 && unselected.stderr.contains("Permission denied"),
              "the server enrolled under another principal rejects the certificate: \(unselected.stderr)")
        let bare = try e2e.ssh(argv, ["-o", "PubkeyAcceptedAlgorithms=ssh-ed25519"], command: ["true"])
        check(bare.status != 0, "the bare temporary key is rejected")
        let pty = try e2e.ssh(argv, ["-tt"], command: ["true"])
        check(pty.stderr.contains("PTY allocation request failed"), "no PTY by default: \(pty.stderr)")
        let forward = try e2e.ssh(argv, ["-N", "-o", "ClearAllForwardings=no", "-o", "ExitOnForwardFailure=yes",
                                         "-R", "127.0.0.1:0:127.0.0.1:22"])
        check(forward.status != 0 && forward.stderr.contains("forwarding failed"), "port forwarding denied by the server: \(forward.stderr)")
        let elsewhere = try run("/usr/bin/ssh", ["-F", directory.sshConfig.path, "e2e-c", "true"])
        check(elsewhere.status != 0, "a name outside the grant goes nowhere")

        let status = e2e.json(try e2e.cli(["access", "status", "--json"]))
        check(status?["status"] as? String == "active" && status?["grant_id"] as? String == grantId, "status reports it")
        check(e2e.argv(status) == argv, "status returns the same argv")
        let second = try e2e.cli(["access", "srv-c", "--for", "1m", "--json"])
        check(second.status == 1 && e2e.errorCode(second) == "access_already_active", "one grant at a time: \(second.stdout)")
        check(((e2e.json(second)?["active_grant"] as? [String: Any])?["grant_id"] as? String) == grantId, "details of the active grant")
        check(e2e.grantDirectories == [grantId], "no second grant directory")
        let summary = try e2e.entry("srv-a")?.temporaryAccess?.lastGrant
        check(summary?.grantId == grantId && summary?.sshAlias == targets.first?["ssh_alias"] as? String && summary?.endedAt == nil,
              "inventory keeps the latest grant summary")
        check(try e2e.entry("srv-c")?.temporaryAccess?.lastGrant == nil, "only for the selected targets")
        let human = try e2e.cli(["access", "status"])
        check(human.stdout.contains("ssh -F") && human.stdout.contains("is active until"), "human status: \(human.stdout)")
    }

    test("access stop: no new logins, files removed, old argv fails without falling back") {
        guard let grantId = grant?["grant_id"] as? String else { check(false, "no grant"); return }
        let job = e2e.jobProcess(grantId)
        let stopped = try e2e.cli(["access", "stop", "--json"])
        check(stopped.status == 0 && e2e.json(stopped)?["status"] as? String == "stopped", "stopped: \(stopped.stdout)")
        check(job.map { !$0.isRunning } == true, "the job exited")
        check(e2e.grantDirectories.isEmpty, "grant files removed")
        let old = try e2e.ssh(e2e.argv(grant), command: ["true"])
        check(old.status == 255 && old.stderr.contains("Can't open user config file"), "old command fails: \(old.stderr)")
        check(e2e.json(try e2e.cli(["access", "status", "--json"]))?["status"] as? String == "inactive", "inactive")
        check(try e2e.entry("srv-a")?.temporaryAccess?.lastGrant?.endReason == "stopped", "end reason recorded")
        check(e2e.json(try e2e.cli(["access", "stop", "--json"]))?["status"] as? String == "inactive", "stop again is harmless")
    }

    test("--force-command and --allow-pty: the forced command wins, PTY allowed, forwarding still denied") {
        let forced = "touch /tmp/forced-ran; echo forced-$(whoami)"
        let result = try e2e.cli(["access", "srv-a", "--for", "2m", "--force-command", forced, "--allow-pty", "--json"])
        let document = e2e.json(result)
        check(result.status == 0, "granted: \(result.stdout) \(result.stderr.suffix(500))")
        check((document?["permissions"] as? [String: Any])?["force_command"] as? String == forced, "permissions")
        // The readiness check authenticated without opening a session.
        check(try e2e.onServer("a", "ls /tmp/forced-ran 2>/dev/null || echo absent").stdout.contains("absent"),
              "the forced command did not run during the readiness check")
        let output = try e2e.ssh(e2e.argv(document), command: ["echo", "requested"])
        check(output.stdout.contains("forced-tester") && !output.stdout.contains("requested"), "forced command ran: \(output.stdout)")
        let pty = try e2e.ssh(e2e.argv(document), ["-tt"], command: ["true"])
        check(!pty.stderr.contains("PTY allocation request failed") && pty.stdout.contains("forced-tester"), "PTY allowed: \(pty.stderr)")
        let forward = try e2e.ssh(e2e.argv(document), ["-N", "-o", "ClearAllForwardings=no", "-o", "ExitOnForwardFailure=yes",
                                                       "-R", "127.0.0.1:0:127.0.0.1:22"])
        check(forward.status != 0, "forwarding still denied")
        _ = try e2e.cli(["access", "stop", "--json"])
    }

    test("the readiness check is not satisfied by another key") {
        // A config that logs in with the bootstrap key: authentication succeeds,
        // but not with the certificate the check expects.
        let other = e2e.work.appendingPathComponent("ssh_config_other")
        try """
        Host other
          HostName 127.0.0.1
          Port \(e2e.servers["a"]!.port)
          User tester
          IdentityFile \(e2e.bootstrap.path)
          IdentitiesOnly yes
          IdentityAgent none
          BatchMode yes
          ControlPath none
          StrictHostKeyChecking no
          UserKnownHostsFile \(e2e.knownHosts.path)
        """.write(to: other, atomically: true, encoding: .utf8)
        let outcome = CertificateLoginCheck.run(configFile: other, alias: "other", keyFingerprint: "SHA256:not-the-bootstrap-key")
        check(outcome == .failed("authenticated with something other than the certificate"), "rejected: \(outcome)")
    }

    test("expiry: open sessions continue, new logins and held agent connections fail, files removed") {
        let result = try e2e.cli(["access", "srv-b", "--for", "20s", "--json"])
        let document = e2e.json(result)
        guard result.status == 0, let grantId = document?["grant_id"] as? String else {
            check(false, "granted: \(result.stdout) \(result.stderr)")
            return
        }
        let directory = GrantDirectory(paths: e2e.paths, grantId: grantId)
        let session = Process()
        session.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        let argv = e2e.argv(document)
        session.arguments = Array(argv.dropFirst()) + ["sleep 26; echo survived"]
        let output = Pipe()
        session.standardOutput = output
        session.standardError = FileHandle.nullDevice
        try session.run()
        let held = AgentClient.connect(socketPath: directory.agentSocket.path)
        let expires = (document?["remaining_seconds"] as? Int) ?? 20
        check(e2e.waitUntil(Double(expires) + 15) { !FileManager.default.fileExists(atPath: directory.url.path) },
              "files removed at expiry")
        if let held {
            var writer = SSHWriter()
            writer.writeByte(13)
            writer.writeString(Data([1]))
            writer.writeString(Data([2]))
            writer.writeUInt32(0)
            let sent = SocketIOForTests.write(held, AgentProtocol.frame(writer.data))
            let reply = sent ? SocketIOForTests.read(held) : nil
            check(reply == nil || reply == AgentProtocol.failure, "the connection opened before expiry gets no signature")
            close(held)
        }
        let fresh = try e2e.ssh(argv, command: ["true"])
        check(fresh.status != 0, "a new login after expiry fails")
        session.waitUntilExit()
        let survived = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        check(survived.contains("survived"), "the session opened before expiry kept running")
        check(try e2e.entry("srv-b")?.temporaryAccess?.lastGrant?.endReason == "expired", "end reason expired")
    }

    test("a crashed job leaves no usable grant; cleanup removes only its files and reconciles the inventory") {
        let result = try e2e.cli(["access", "srv-a", "--for", "2m", "--json"])
        let document = e2e.json(result)
        guard let grantId = document?["grant_id"] as? String, let job = e2e.jobProcess(grantId) else {
            check(false, "granted: \(result.stdout) \(result.stderr)")
            return
        }
        kill(job.pid, SIGKILL)
        check(e2e.waitUntil(5) { !job.isRunning }, "job killed")
        let after = try e2e.ssh(e2e.argv(document), command: ["true"])
        check(after.status != 0, "no login without the job (no fallback key): \(after.stderr)")
        let status = e2e.json(try e2e.cli(["access", "status", "--json"]))
        check(status?["status"] as? String == "inactive" && status?["cleanup_suggested"] as? Bool == true,
              "status: inactive, cleanup suggested: \(String(describing: status))")
        check(e2e.grantDirectories == [grantId], "status changed nothing")
        let cleaned = e2e.json(try e2e.cli(["access", "cleanup", "--json"]))
        check(((cleaned?["removed"] as? [[String: Any]])?.first?["grant_id"] as? String) == grantId, "removed: \(String(describing: cleaned))")
        check(e2e.grantDirectories.isEmpty, "files gone")
        check(try e2e.entry("srv-a")?.temporaryAccess?.lastGrant?.endReason == "abandoned", "inventory reconciled")
        check(try e2e.entry("srv-a")?.temporaryAccess?.verified == true, "CA enrollment kept")
        check(try e2e.authorizedKeys("a").contains(e2e.ca.publicKeyBlob.base64EncodedString()), "server trust untouched")
    }

    test("a target that no longer accepts the certificate withdraws the whole grant") {
        let caKey = e2e.ca.publicKeyBlob.base64EncodedString()
        try e2e.onServer("b", "f=$HOME/.ssh/authorized_keys; grep -vF '\(caKey)' $f > $f.n; cat $f.n > $f; rm $f.n")
        let result = try e2e.cli(["access", "srv-a,srv-b", "--for", "1m", "--json"])
        check(result.status == 1 && e2e.errorCode(result) == "readiness_failed", "readiness failed: \(result.stdout)")
        let failed = (e2e.json(result)?["failed_targets"] as? [[String: Any]])?.compactMap { $0["inventory_alias"] as? String }
        check(failed == ["srv-b"], "names the failing target: \(String(describing: failed))")
        check(e2e.grantDirectories.isEmpty, "nothing left")
        let restored = try e2e.cli(["authorize", "e2e-b", "-F", e2e.config.path, "--alias", "srv-b", "--temporary-access"])
        check(restored.status == 0, "authorize restores the line: \(restored.stdout.suffix(300))")
    }

    test("an interrupted request (killed CLI) withdraws the grant") {
        _ = try run(e2e.docker, ["pause", e2e.servers["b"]!.container])
        let process = Process()
        process.executableURL = URL(fileURLWithPath: cliBinary)
        process.arguments = ["access", "srv-a,srv-b", "--for", "1m", "--json"]
        process.environment = ProcessInfo.processInfo.environment.merging(e2e.environment) { $1 }
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        check(e2e.waitUntil(15) {
            e2e.grantDirectories.contains { FileManager.default.fileExists(atPath: GrantDirectory(paths: e2e.paths, grantId: $0).agentSocket.path) }
        }, "issued and checking the servers")
        let grantId = e2e.grantDirectories.first ?? ""
        let job = e2e.jobProcess(grantId)
        kill(process.processIdentifier, SIGKILL)
        process.waitUntilExit()
        check(e2e.waitUntil(15) { e2e.grantDirectories.isEmpty }, "grant withdrawn after the caller died")
        check(job.map { !$0.isRunning } ?? true, "job exited")
        _ = try run(e2e.docker, ["unpause", e2e.servers["b"]!.container])
    }

    test("audit checks the CA scope, not only its presence") {
        let audited = try e2e.cli(["audit", "srv-a", "srv-b", "srv-c"])
        check(audited.status == 0 && audited.stdout.contains("CA trust scoped"), "audit passes: \(audited.stdout.suffix(800))")
        let caKey = e2e.ca.publicKeyBlob.base64EncodedString()
        // Someone broadens server c's line: no principals= restriction any more.
        try e2e.onServer("c", "f=$HOME/.ssh/authorized_keys; grep -vF '\(caKey)' $f > $f.n; "
            + "echo 'cert-authority,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ecdsa-sha2-nistp256 \(caKey) x' >> $f.n; "
            + "cat $f.n > $f; rm $f.n")
        let broader = try e2e.cli(["audit", "srv-c"])
        check(broader.status != 0 && broader.stdout.contains("broader than expected"), "broadened line reported: \(broader.stdout.suffix(600))")
        check(try e2e.entry("srv-c")?.temporaryAccess?.lastAuditResult?.contains("broader") == true, "result recorded")
        let listed = try e2e.cli(["inventory"])
        check(listed.stdout.contains("temporary access") && listed.stdout.contains(e2e.ca.fingerprint), "inventory shows enrollment")
        let status = try e2e.cli(["status"])
        check(status.stdout.contains("Temporary CA:") && status.stdout.contains(e2e.ca.fingerprint), "status shows the CA: \(status.stdout)")
    }

    test("the grant job runs under launchd with its own label, no KeepAlive, and leaves nothing behind") {
        let result = try e2e.cli(["access", "srv-a", "--for", "2m", "--json"], launchd: true)
        let document = e2e.json(result)
        guard result.status == 0, let grantId = document?["grant_id"] as? String else {
            check(false, "launchd grant: \(result.stdout) \(result.stderr.suffix(600))")
            return
        }
        let label = AccessLauncher.label(paths: e2e.paths, grantId: grantId)
        let printed = try run("/bin/launchctl", ["print", "gui/\(getuid())/\(label)"])
        check(printed.status == 0, "launchd knows the job: \(printed.stderr)")
        let directory = GrantDirectory(paths: e2e.paths, grantId: grantId)
        let plist = (try? PropertyListSerialization.propertyList(from: Data(contentsOf: directory.plist), format: nil)) as? [String: Any]
        check(plist?["KeepAlive"] as? Bool == false && plist?["LaunchOnlyOnce"] as? Bool == true, "no restart")
        check(try e2e.ssh(e2e.argv(document), command: ["echo", "launchd-ok"]).stdout.contains("launchd-ok"), "works")
        check(try e2e.cli(["access", "stop", "--json"]).status == 0, "stopped")
        check(e2e.waitUntil(10) { try! run("/bin/launchctl", ["print", "gui/\(getuid())/\(label)"]).status != 0 }, "label removed")
        check(e2e.grantDirectories.isEmpty, "files removed")
    }

    test("deauthorize removes the CA line with the other keys of this Mac") {
        let before = try e2e.authorizedKeys("c")
        check(before.contains(e2e.ca.publicKeyBlob.base64EncodedString()), "CA there first")
        let result = try expectScript(#"""
        spawn $env(CLI) deauthorize srv-c -F $env(CFG)
        expect {
          "to take this Mac" { send -- "REMOVE\r"; exp_continue }
          timeout { puts "\nRESULT=hung"; exit 3 }
          eof
        }
        catch wait result
        puts "\nEXIT=[lindex $result 3]"
        """#, paths: e2e.paths, extra: ["CFG": e2e.config.path], in: e2e.work)
        check(result.stdout.contains("EXIT=0"), "deauthorize: \(result.stdout.suffix(500))")
        let after = try e2e.authorizedKeys("c")
        check(!after.contains(e2e.ca.publicKeyBlob.base64EncodedString()), "CA line removed")
        check(after.contains(e2e.bootstrapLine), "other keys kept")
        check(try e2e.entry("srv-c") == nil, "dropped from the inventory")
    }

    test("a server that refuses certificates is recorded unverified, and access refuses it") {
        try e2e.startServer("d", extra: "PubkeyAcceptedAlgorithms -ssh-ed25519-cert-v01@openssh.com")
        let result = try e2e.cli(["authorize", "e2e-d", "-F", e2e.config.path, "--alias", "srv-d", "--temporary-access"])
        check(result.status == 1 && result.stdout.contains("did not accept a certificate from this CA"),
              "enrollment refused: \(result.stdout.suffix(500))")
        check(try e2e.entry("srv-d")?.temporaryAccess?.verified == false, "recorded as not confirmed")
        check(try e2e.entry("srv-d")?.loginKeyFingerprint == e2e.agent.identity.fingerprint, "the login keys are still recorded")
        let refused = try e2e.cli(["access", "srv-d", "--for", "1m", "--json"])
        check(e2e.errorCode(refused) == "not_enrolled", "access refuses it: \(refused.stdout)")
    }

    test("a replaced CA: authorize moves the server to the new CA and removes the old one") {
        // As after changed fingerprints invalidated the CA and it was replaced.
        let previous = e2e.ca
        let principal = try e2e.entry("srv-b")?.temporaryAccess?.principal
        try FileManager.default.removeItem(at: e2e.paths.caKeyFile)
        try FileManager.default.removeItem(at: e2e.paths.caPublicKeyFile)
        let replacement = try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: e2e.paths)
        let mismatch = try e2e.cli(["access", "srv-b", "--for", "1m", "--json"])
        check(e2e.errorCode(mismatch) == "ca_mismatch", "the old enrollment no longer matches: \(mismatch.stdout)")
        let result = try e2e.cli(["authorize", "e2e-b", "-F", e2e.config.path, "--alias", "srv-b", "--temporary-access"])
        check(result.status == 0 && result.stdout.contains("Removed the previous CA"), "rotated: \(result.stdout.suffix(600))")
        let keys = try e2e.authorizedKeys("b")
        check(!keys.contains(previous.publicKeyBlob.base64EncodedString()), "old CA line removed")
        check(keys.components(separatedBy: replacement.publicKeyBlob.base64EncodedString()).count == 2, "one new CA line")
        let enrollment = try e2e.entry("srv-b")?.temporaryAccess
        check(enrollment?.caFingerprint == replacement.fingerprint && enrollment?.retiredCAFingerprints == [previous.fingerprint]
              && enrollment?.caRotation == nil && enrollment?.principal == principal, "record moved to the new CA, same principal")
        let granted = try e2e.cli(["access", "srv-b", "--for", "1m", "--json"])
        check(granted.status == 0, "access works with the new CA: \(granted.stdout)")
        _ = try e2e.cli(["access", "stop", "--json"])
    }

    test("the personal ssh config is never changed") {
        check((try? Data(contentsOf: personalConfig)) == personalBefore, "~/.ssh/config unchanged")
    }
}

/// Runs `recover` (or `recovery test`) through expect, answering the prompts.
func recoverWithExpect(_ e2e: AccessE2E, _ command: String, kit: URL, inventory: URL, config: URL,
                       paths: AgentPaths, extra: String = "", interrupt: String = "") throws -> ShellResult {
    try expectScript(#"""
    set timeout 240
    spawn $env(CLI) {*}$env(CMD) $env(KIT) --inventory $env(INV) -F $env(CFG) {*}$env(EXTRA)
    expect {
      "Type RECOVER" { send -- "RECOVER\r"; exp_continue }
      "or Enter to skip" { send -- "\r"; exp_continue }
      "Add it to" { send -- "n\r"; exp_continue }
      "Add them?" { send -- "n\r"; exp_continue }
      "Replace the emergency key" { puts "\nRESULT=asked-to-replace"; exit 5 }
      "Retype the passphrase" { puts "\nRESULT=asked-for-new-kit"; exit 4 }
      timeout { puts "\nRESULT=hung"; exit 3 }
      eof
    }
    catch wait result
    puts "\nEXIT=[lindex $result 3]"
    """#, paths: paths, extra: ["CMD": command, "KIT": kit.path, "INV": inventory.path, "CFG": config.path, "EXTRA": extra,
                                 AccessLauncher.modeVariable: "process", "TOUCHID_SSH_AGENT_TEST_INTERRUPT": interrupt],
       in: e2e.work)
}

func runRecoveryCADockerTests(docker: String, image: String) {
    print("Recovery of temporary-access CA trust (Docker)")
    let old: AccessE2E
    let newMac: LiveAgent
    do {
        old = try AccessE2E(docker: docker, image: image)
        newMac = try LiveAgent.start(shortPath: true)
    } catch {
        test("recovery setup") { throw error }
        return
    }
    defer {
        _ = try? old.cli(["access", "stop", "--json"])
        newMac.stop()
        old.stop()
    }
    let cloud = old.work.appendingPathComponent("cloud")
    let backup = cloud.appendingPathComponent(InventoryBackup.fileName)
    let newConfig = old.work.appendingPathComponent("ssh_config_new")
    let newKnownHosts = old.work.appendingPathComponent("known_hosts_new")
    let older = SoftwareCA()   // a CA the lost Mac was itself replacing
    var newCA: StoredIdentity?
    var oldGrant: [String: Any]?
    var originalBackup = Data()
    var r4Principal: String?
    let oldCA = old.ca.publicKeyBlob.base64EncodedString()
    let olderCA = older.blob.base64EncodedString()
    let oldLogin = old.agent.identity.publicKeyBlob.base64EncodedString()
    let kitKey = (try? RecoveryKey(line: String(contentsOf: old.kit.publicKey, encoding: .utf8)))?.blob.base64EncodedString() ?? "?"
    func newEnvironment(_ arguments: [String]) throws -> ShellResult {
        try run(cliBinary, arguments, environment: [AgentPaths.environmentVariable: newMac.paths.directory.path,
                                                    AccessLauncher.modeVariable: "process"])
    }
    func local(_ alias: String) throws -> InventoryEntry? {
        try InventoryStore.load(from: newMac.paths).servers.first { $0.alias == alias }
    }
    /// The bootstrap-free way the new Mac reaches a server: the kit's plain key.
    func kitAccess() -> [String] {
        ["--", "-i", old.kit.kit.path, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=accept-new"]
    }

    test("recovery setup: the old Mac enrolls four servers, one with an unfinished CA replacement, and holds a live grant") {
        for name in ["r1", "r2", "r3", "r4"] {
            try old.startServer(name)
            let result = try old.cli(["authorize", "e2e-\(name)", "-F", old.config.path, "--alias", "srv-\(name)", "--temporary-access"])
            check(result.status == 0, "authorize \(name): \(result.stdout.suffix(300))")
        }
        // A duplicate of the old CA line on r3, as a hand edit might leave.
        let line = try old.authorizedKeys("r3").split(separator: "\n").first { $0.contains(oldCA) }.map(String.init) ?? ""
        try old.onServer("r3", "printf '%s\\n' '\(line)' >> $HOME/.ssh/authorized_keys")
        check(try old.authorizedKeys("r3").components(separatedBy: oldCA).count == 3, "two old CA lines on r3")
        // r4 still trusts an older CA that the lost Mac was replacing, and its
        // record says so (caRotation), as an interrupted replacement leaves it.
        guard let r4 = try old.entry("srv-r4")?.temporaryAccess else { check(false, "r4 enrolled"); return }
        let olderLine = "\(CATrust.options(principal: r4.principal)) \(SSHKeyFormat.keyType) \(olderCA) older-ca"
        try old.onServer("r4", "printf '%s\\n' '\(olderLine)' >> $HOME/.ssh/authorized_keys")
        try InventoryStore.update(old.paths) { inventory in
            for index in inventory.servers.indices where inventory.servers[index].alias == "srv-r4" {
                inventory.servers[index].temporaryAccess?.caRotation = CARotation(
                    recoveryId: "authorize-1", oldCAPublicKey: SSHKeyFormat.authorizedKeyLine(blob: older.blob, comment: "older-ca"),
                    oldCAFingerprint: older.fingerprint, newCAPublicKey: r4.caPublicKey, newCAFingerprint: r4.caFingerprint,
                    principal: r4.principal, authorizedKeyOptions: r4.authorizedKeyOptions, step: .replacementVerified,
                    updatedAt: .wholeSecondsNow)
            }
        }
        check(InventoryBackup.export(paths: old.paths).isWritten, "backup written with the pending replacement")
        originalBackup = (try? Data(contentsOf: backup)) ?? Data()

        let granted = try old.cli(["access", "srv-r1,srv-r3", "--for", "10m", "--json"])
        oldGrant = old.json(granted)
        check(granted.status == 0, "old grant: \(granted.stdout) \(granted.stderr.suffix(400))")
        for index in 0..<2 {
            check(try old.ssh(old.argv(oldGrant, index), command: ["echo", "old-ok"]).stdout.contains("old-ok"),
                  "the old certificate logs in before recovery")
        }
        try "Host *\n  UserKnownHostsFile \(newKnownHosts.path)\n  LogLevel ERROR\n".write(to: newConfig, atomically: true, encoding: .utf8)
        newCA = try CertificateAuthorityStore.createWithoutUserPresenceForTesting(in: newMac.paths)
        try SettingsStore.save(AgentSettings(backupPath: cloud.path), to: newMac.paths)
    }

    test("recovery test reports the recorded CA trust and changes nothing") {
        let probe = try LiveAgent.start(shortPath: true)
        defer { probe.stop() }
        let before = try ["r1", "r2", "r3", "r4"].map { try old.authorizedKeys($0) }
        let result = try recoverWithExpect(old, "recovery test", kit: old.kit.kit, inventory: backup, config: newConfig, paths: probe.paths)
        check(result.stdout.contains("EXIT=0"), "dry run passed: \(result.stdout.suffix(500))")
        check(result.stdout.components(separatedBy: "temporary access: CA trust scoped").count == 5, "CA trust reported for each server")
        check(result.stdout.contains("2 duplicate CA lines"), "the duplicate is reported")
        check(try ["r1", "r2", "r3", "r4"].map { try old.authorizedKeys($0) } == before, "authorized_keys unchanged")
        check(!FileManager.default.fileExists(atPath: probe.paths.caKeyFile.path), "no CA created by recovery test")
    }

    test("the new Mac enrolls r4 itself before recovering it") {
        guard newCA != nil else { check(false, "no new CA"); return }
        try RecoveryStore.importPublicKey(from: old.kit.publicKey, into: newMac.paths, replace: false)
        // A freshly installed Mac has no backup folder yet, so this authorize
        // writes no backup over the old Mac's one.
        try SettingsStore.save(AgentSettings(), to: newMac.paths)
        defer { try? SettingsStore.save(AgentSettings(backupPath: cloud.path), to: newMac.paths) }
        let result = try newEnvironment(["authorize", "tester@127.0.0.1", "-p", old.servers["r4"]!.port, "-F", newConfig.path,
                                         "--alias", "srv-r4", "--temporary-access"] + kitAccess())
        check((try? Data(contentsOf: backup)) == originalBackup, "the old Mac's backup is untouched")
        check(result.status == 0, "authorize on the new Mac: \(result.stdout.suffix(400)) \(result.stderr.suffix(300))")
        r4Principal = try local("srv-r4")?.temporaryAccess?.principal
        check(try old.authorizedKeys("r4").contains(oldCA), "the lost Mac's CA is still trusted on r4")
    }

    test("recover, interrupted: each moved server is saved at once; a failed CA check never keeps old credentials") {
        guard let newCA else { check(false, "no new CA"); return }
        // r2 stops accepting certificates, so this Mac's CA cannot be confirmed there.
        let refuse = try run(docker, ["exec", old.servers["r2"]!.container, "sh", "-c",
                                      "echo 'PubkeyAcceptedAlgorithms -ssh-ed25519-cert-v01@openssh.com' > /etc/ssh/sshd_config.d/zz-test.conf; kill -HUP 1"])
        check(refuse.status == 0, "sshd reconfigured: \(refuse.stderr)")
        usleep(800_000)
        // The run dies right after r3's old keys are removed, before it is recorded.
        let result = try recoverWithExpect(old, "recover", kit: old.kit.kit, inventory: backup, config: newConfig,
                                           paths: newMac.paths, extra: "--keep-emergency-key", interrupt: "after-removal:srv-r3")
        let output = result.stdout
        check(output.contains("EXIT=99"), "the run was interrupted on r3: \(output.suffix(900))")
        check(output.contains("Temporary-access CA: \(newCA.fingerprint)") && output.contains("validation certificate"),
              "explains the CA and the validation certificate")
        check((try? Data(contentsOf: backup)) == originalBackup, "backup left as it was")
        let copies = ((try? FileManager.default.contentsOfDirectory(atPath: cloud.path)) ?? []).filter { $0.hasPrefix("inventory-before-recovery-") }
        check(copies.count == 1 && (try? Data(contentsOf: cloud.appendingPathComponent(copies[0]))) == originalBackup,
              "a copy of the backup the kit opens was kept before any change: \(copies)")
        let newCABase64 = newCA.publicKeyBlob.base64EncodedString()
        for name in ["r1", "r2", "r3"] {
            let keys = try old.authorizedKeys(name)
            check(!keys.contains(oldCA) && !keys.contains(oldLogin), "\(name): the lost Mac's key and every old CA line removed")
            check(keys.contains(newCABase64) && keys.contains(newMac.identity.publicKeyBlob.base64EncodedString()) && keys.contains(kitKey),
                  "\(name): this Mac's CA and login key, and the kept emergency key")
        }
        for index in 0..<2 {
            let fresh = try old.ssh(old.argv(oldGrant, index), command: ["true"])
            check(fresh.status != 0 && fresh.stderr.contains("Permission denied"),
                  "the old, still-valid certificate fails fresh authentication after its CA was removed: \(fresh.stderr)")
        }
        let r1 = try local("srv-r1")?.temporaryAccess
        check(r1?.verified == true && r1?.caFingerprint == newCA.fingerprint && r1?.caRotation == nil
              && r1?.retiredCAFingerprints == [old.ca.fingerprint] && r1?.lastGrant == nil, "r1 saved at once, complete, no grant restored")
        let r2 = try local("srv-r2")
        check(r2?.loginKeyFingerprint == newMac.identity.fingerprint && r2?.temporaryAccess?.verified == false
              && r2?.temporaryAccess?.caRotation == nil, "r2 moved; only temporary access left unconfirmed")
        check(output.contains("temporary access not confirmed"), "the unconfirmed CA is reported")
        let r3 = try local("srv-r3")
        check(r3?.loginKeyFingerprint == old.agent.identity.fingerprint && r3?.temporaryAccess?.caRotation?.step == .retirementStarted,
              "r3's record still shows the interrupted step")
        check(try old.authorizedKeys("r4").contains(oldCA), "r4 not reached yet")
        check(((try? FileManager.default.contentsOfDirectory(atPath: newMac.paths.grantsDirectory.path)) ?? []).isEmpty,
              "no grant directory on the new Mac")
        let refused = try newEnvironment(["access", "srv-r2", "--for", "1m", "--json"])
        check(old.errorCode(refused) == "not_enrolled", "an unconfirmed server cannot get a grant: \(refused.stdout)")
    }

    test("recover again: the interrupted server finishes through the Touch ID key; nothing done is redone") {
        guard let newCA else { check(false, "no new CA"); return }
        // As if the interrupted run had replaced the emergency key: the kit no longer opens r3.
        try old.onServer("r3", "f=$HOME/.ssh/authorized_keys; grep -vF '\(kitKey)' $f > $f.n; cat $f.n > $f; rm $f.n")
        let result = try recoverWithExpect(old, "recover", kit: old.kit.kit, inventory: backup, config: newConfig,
                                           paths: newMac.paths, extra: "--keep-emergency-key")
        let output = result.stdout
        check(output.contains("EXIT=0"), "recover finished: \(output.suffix(900))")
        check(output.components(separatedBy: "already moved to this Mac by an earlier run; skipped").count == 3, "r1 and r2 skipped")
        check(output.contains("finishing through the Touch ID key"), "r3 resumed through this Mac's key")
        check(try old.authorizedKeys("r3").contains(kitKey), "r3 has the emergency key again")
        let r4Keys = try old.authorizedKeys("r4")
        check(!r4Keys.contains(oldCA) && !r4Keys.contains(olderCA) && !r4Keys.contains(oldLogin),
              "r4: the lost Mac's CA, the CA it was replacing and its login key are gone")
        let r4 = try local("srv-r4")?.temporaryAccess
        check(r4?.principal == r4Principal && r4?.caFingerprint == newCA.fingerprint && r4?.verified == true
              && Set(r4?.retiredCAFingerprints ?? []) == [old.ca.fingerprint, older.fingerprint],
              "r4 keeps this Mac's own enrollment and records both retired CAs")
        check(r4Keys.contains(CATrust.options(principal: r4Principal ?? "-")), "r4's CA line keeps this Mac's principal")
        let servers = try InventoryStore.load(from: newMac.paths).servers
        check(servers.count == 4 && servers.allSatisfy { $0.loginKeyFingerprint == newMac.identity.fingerprint
                                                         && $0.temporaryAccess?.caRotation == nil }, "every server moved")
        check(output.contains("Temporary access is not confirmed yet on: srv-r2"), "r2 still listed for authorize")
        let decrypted = try run(agePath ?? "age", ["-d", "-i", old.kit.kit.path, backup.path])
        check(decrypted.stdout.contains(newCA.fingerprint) && !decrypted.stdout.contains("caRotation"),
              "the new backup holds the new CA trust")

        // r2 accepts certificates again; authorize confirms its CA.
        _ = try run(docker, ["exec", old.servers["r2"]!.container, "sh", "-c", "rm /etc/ssh/sshd_config.d/zz-test.conf; kill -HUP 1"])
        usleep(800_000)
        let fixed = try newEnvironment(["authorize", "tester@127.0.0.1", "-p", old.servers["r2"]!.port, "-F", newConfig.path,
                                        "--alias", "srv-r2", "--temporary-access", "--",
                                        "-o", "IdentityAgent=\(newMac.socket)", "-o", "IdentityFile=\(newMac.paths.publicKeyFile.path)",
                                        "-o", "IdentitiesOnly=yes"])
        check(try fixed.status == 0 && local("srv-r2")?.temporaryAccess?.verified == true, "authorize confirms r2: \(fixed.stdout.suffix(300))")
        let granted = try newEnvironment(["access", "srv-r1,srv-r2", "--for", "1m", "--json"])
        let document = old.json(granted)
        check(granted.status == 0, "the new Mac grants access through its CA: \(granted.stdout) \(granted.stderr.suffix(300))")
        check(try old.ssh(old.argv(document, 1), command: ["echo", "new-ok"]).stdout.contains("new-ok"), "new certificate works on r2")
        _ = try newEnvironment(["access", "stop", "--json"])
        let audited = try newEnvironment(["audit", "srv-r1", "srv-r3", "srv-r4"])
        check(audited.status == 0 && !audited.stdout.contains("retired CA is still trusted"), "audit passes: \(audited.stdout.suffix(400))")
    }
}

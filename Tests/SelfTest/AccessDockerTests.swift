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
        let result = try e2e.cli(["access", "srv-a, srv-b", "--for", "3m", "--json"])
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

    test("the personal ssh config is never changed") {
        check((try? Data(contentsOf: personalConfig)) == personalBefore, "~/.ssh/config unchanged")
    }
}

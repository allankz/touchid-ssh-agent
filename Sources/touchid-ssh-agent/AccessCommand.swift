import Darwin
import Foundation
import TouchIDSSHCore

// `access`: temporary SSH access. Results go to stdout (one JSON document with
// --json); the approval summary and progress always go to stderr, so a caller
// parsing stdout never sees prose.

struct AccessFailure: Error {
    let code: String
    let message: String
    var details: [String: Any] = [:]

    init(_ code: String, _ message: String, details: [String: Any] = [:]) {
        self.code = code
        self.message = message
        self.details = details
    }

    var exitCode: Int32 { code == "invalid_arguments" || code == "invalid_duration" ? 2 : 1 }
}

/// Writes the command's result and progress.
struct AccessReporter {
    let json: Bool

    /// Progress and summaries: always stderr.
    func progress(_ text: String = "") {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        let body = lines.map { $0.isEmpty ? "" : Out.margin + $0 }.joined(separator: "\n")
        FileHandle.standardError.write(Data((body + "\n").utf8))
    }

    /// The single JSON document on stdout.
    func emit(_ document: [String: Any]) {
        var document = document
        document["schema_version"] = 1
        let data = (try? JSONSerialization.data(withJSONObject: document,
                                                options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])) ?? Data("{}".utf8)
        FileHandle.standardOutput.write(data + Data("\n".utf8))
    }

    func fail(_ failure: AccessFailure) -> Never {
        if json {
            var document = failure.details
            document["ok"] = false
            document["status"] = "error"
            document["error"] = ["code": failure.code, "message": failure.message]
            emit(document)
        }
        progress("error: \(failure.message)")
        exit(failure.exitCode)
    }
}

let accessUsage = """
usage: \(tool) access HOST[,HOST...] --for DURATION [--force-command COMMAND] [--allow-pty] [--json]
       \(tool) access status|stop|cleanup [--json]
       \(tool) access help
"""

/// Entry point: never returns.
func access(_ arguments: ArraySlice<String>, paths: AgentPaths) -> Never {
    let args = Array(arguments)
    let reporter = AccessReporter(json: args.contains("--json"))
    do {
        switch args.first {
        case nil:
            throw AccessFailure("invalid_arguments", "missing hosts or subcommand.\n\(accessUsage)")
        case "help", "--help", "-h":
            guard args.count == 1 else { throw AccessFailure("invalid_arguments", accessUsage) }
            print(accessHelp)
            exit(0)
        case "status", "stop", "cleanup":
            let subcommand = args[0]
            let rest = args.dropFirst().filter { $0 != "--json" }
            guard rest.isEmpty, args.filter({ $0 == "--json" }).count <= 1 else {
                throw AccessFailure("invalid_arguments", """
                `access \(subcommand)` takes only --json. To request a host named "\(subcommand)", \
                use its user@host form or include it in a comma-separated list.
                """)
            }
            switch subcommand {
            case "status": accessStatus(paths: paths, reporter: reporter)
            case "stop": try accessStop(paths: paths, reporter: reporter)
            default: try accessCleanup(paths: paths, reporter: reporter)
            }
            exit(0)
        default:
            let request = try AccessArguments(args)
            try issueAccess(request, paths: paths, reporter: reporter)
            exit(0)
        }
    } catch let failure as AccessFailure {
        reporter.fail(failure)
    } catch let error as AccessError {
        reporter.fail(AccessFailure(error.code, error.description))
    } catch {
        reporter.fail(AccessFailure("internal_error", "\(error)"))
    }
}

// MARK: - Arguments

struct AccessArguments {
    var hosts: [String]
    var duration: UInt64
    var permissions = AccessPermissions()

    init(_ args: [String]) throws {
        var hostList: String?
        var forText: String?
        var forceCommand: String?
        var allowPTY = false
        var seen = Set<String>()
        var index = 0
        func value(_ name: String, inline: String?) throws -> String {
            if let inline { return inline }
            index += 1
            guard index < args.count else { throw AccessFailure("invalid_arguments", "\(name) needs a value.\n\(accessUsage)") }
            return args[index]
        }
        while index < args.count {
            let argument = args[index]
            let parts = argument.split(separator: "=", maxSplits: 1).map(String.init)
            let name = argument.hasPrefix("--") ? parts[0] : argument
            let inline = argument.hasPrefix("--") && parts.count == 2 ? parts[1] : nil
            if argument.hasPrefix("-") {
                guard seen.insert(name).inserted else { throw AccessFailure("invalid_arguments", "\(name) given twice.") }
            }
            switch name {
            case "--for": forText = try value(name, inline: inline)
            case "--force-command": forceCommand = try value(name, inline: inline)
            case "--allow-pty":
                guard inline == nil else { throw AccessFailure("invalid_arguments", "--allow-pty takes no value.") }
                allowPTY = true
            case "--json":
                guard inline == nil else { throw AccessFailure("invalid_arguments", "--json takes no value.") }
            default:
                if argument.hasPrefix("-") {
                    throw AccessFailure("invalid_arguments", "unknown option \(DisplayText.sanitize(argument, maxLength: 40)). "
                        + "Forwarding options are not available in this version.\n\(accessUsage)")
                }
                guard hostList == nil else {
                    throw AccessFailure("invalid_arguments", "give the hosts as one comma-separated argument, such as web,db.\n\(accessUsage)")
                }
                hostList = argument
            }
            index += 1
        }
        guard let hostList else { throw AccessFailure("invalid_arguments", "missing hosts.\n\(accessUsage)") }
        if ["status", "stop", "cleanup", "help"].contains(hostList) {
            throw AccessFailure("invalid_arguments", """
            `\(hostList)` is an access subcommand and takes no other options. To request a host named \
            "\(hostList)", use its user@host form or include it in a comma-separated list.
            """)
        }
        hosts = try AccessArguments.splitHosts(hostList)
        guard let forText else {
            throw AccessFailure("invalid_duration", "--for is required: say how long the access should last, such as --for 30m or --for 2h (at most 12h).")
        }
        duration = try AccessDuration.parse(forText)
        if let forceCommand {
            try AccessPermissions.validateForceCommand(forceCommand)
            permissions.forceCommand = forceCommand
        }
        permissions.pty = allowPTY
    }

    /// Splits on commas and trims each item; empty, option-like or
    /// space-containing items fail the whole request.
    static func splitHosts(_ list: String) throws -> [String] {
        let items = list.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard items.count <= 32 else { throw AccessFailure("invalid_arguments", "at most 32 hosts per grant.") }
        for item in items {
            guard !item.isEmpty else {
                throw AccessFailure("invalid_arguments", "empty host in \"\(DisplayText.sanitize(list, maxLength: 80))\": check the commas.")
            }
            guard !item.hasPrefix("-"), item.count <= 255,
                  !item.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0) }) else {
                throw AccessFailure("invalid_arguments", "invalid host \"\(DisplayText.sanitize(item, maxLength: 60))\".")
            }
        }
        return items
    }
}

// MARK: - Resolving targets

/// Finds the inventory entry each requested item names: an inventory alias, a
/// recorded destination, `user@host`, or anything `ssh -G` resolves to the
/// same hostname, user and port. Every item must match exactly one entry
/// enrolled for temporary access with this Mac's CA.
func resolveAccessTargets(_ items: [String], inventory: Inventory, ca: StoredIdentity) throws -> [(requested: String, entry: InventoryEntry)] {
    var configFiles: [String?] = [nil]
    for file in inventory.servers.compactMap(\.sshConfigFile) where !configFiles.contains(file) { configFiles.append(file) }

    var resolved: [(requested: String, entry: InventoryEntry)] = []
    for item in items {
        var matches = Set<Int>()
        for (index, entry) in inventory.servers.enumerated() {
            if entry.alias == item || entry.destination == item || "\(entry.user)@\(entry.hostname)" == item
                || "\(entry.user)@\(entry.alias)" == item {
                matches.insert(index)
            }
        }
        for configFile in configFiles {
            guard let target = try? RemoteKeys.resolve(SSHTarget(destination: item, configFile: configFile)) else { continue }
            for (index, entry) in inventory.servers.enumerated()
            where entry.hostname == target.hostname && entry.user == target.user && entry.port == target.port {
                matches.insert(index)
            }
        }
        let shown = DisplayText.sanitize(item, maxLength: 60)
        guard !matches.isEmpty else {
            throw AccessFailure("unknown_target", """
            \(shown) is not in the inventory. Enroll it once with: \(tool) authorize \(shown) --temporary-access
            """, details: ["target": item])
        }
        guard matches.count == 1, let index = matches.first else {
            let names = matches.sorted().map { inventory.servers[$0].alias }.joined(separator: ", ")
            throw AccessFailure("ambiguous_target", "\(shown) matches several inventory servers (\(names)). Use one of those names.",
                                details: ["target": item])
        }
        let entry = inventory.servers[index]
        try checkEnrollment(entry, requested: item, ca: ca)
        guard !resolved.contains(where: { $0.entry.temporaryAccess?.targetId == entry.temporaryAccess?.targetId }) else { continue }
        resolved.append((item, entry))
    }
    return resolved
}

func checkEnrollment(_ entry: InventoryEntry, requested: String, ca: StoredIdentity) throws {
    let name = entry.alias
    guard let enrollment = entry.temporaryAccess else {
        throw AccessFailure("not_enrolled", """
        \(name) is in the inventory but not enrolled for temporary access. Enroll it once with: \
        \(tool) authorize \(entry.destination) --temporary-access
        """, details: ["target": requested])
    }
    guard enrollment.caRotation == nil else {
        throw AccessFailure("rotation_pending", """
        \(name) has a CA replacement in progress. Finish it with `\(tool) recover` (new Mac) or \
        `\(tool) authorize \(entry.destination) --temporary-access`.
        """, details: ["target": requested])
    }
    guard enrollment.caFingerprint == ca.fingerprint else {
        throw AccessFailure("ca_mismatch", """
        \(name) trusts another CA (\(enrollment.caFingerprint)), not this Mac's (\(ca.fingerprint)). \
        Run \(tool) authorize \(entry.destination) --temporary-access to move it to this CA.
        """, details: ["target": requested])
    }
    guard enrollment.verified else {
        throw AccessFailure("not_enrolled", """
        \(name)'s enrollment was never confirmed with a certificate login. Run \
        \(tool) authorize \(entry.destination) --temporary-access again.
        """, details: ["target": requested])
    }
    guard !(entry.hostKeys?.isEmpty ?? true) else {
        throw AccessFailure("host_key_missing", "no host key is recorded for \(name). Run `\(tool) audit \(name)` to record it.",
                            details: ["target": requested])
    }
}

/// Builds the frozen target list: inventory identity, recorded host keys and
/// transport settings from the user's configuration. Jump hosts and proxy
/// commands are refused in this version.
func accessTargets(_ resolved: [(requested: String, entry: InventoryEntry)], grantId: String) throws -> [AccessTarget] {
    let aliases = AccessNames.aliases(for: resolved.map(\.entry.alias), grantId: grantId)
    return try zip(resolved, aliases).map { item, alias in
        let entry = item.entry
        guard let enrollment = entry.temporaryAccess else { throw AccessFailure("not_enrolled", "\(entry.alias) is not enrolled") }
        var transport: [String: String] = [:]
        if let effective = try? RemoteKeys.resolve(SSHTarget(destination: entry.destination, port: entry.port, configFile: entry.sshConfigFile)) {
            if let proxy = effective.proxy {
                throw AccessFailure("unsupported_configuration", """
                \(entry.alias) is reached through \(DisplayText.sanitize(proxy, maxLength: 80)). Temporary access does not \
                support jump hosts or proxy commands in this version; use a directly reachable address.
                """, details: ["target": item.requested])
            }
            for keyword in GrantSSHConfig.transportKeywords {
                // "none" means no timeout at all; the grant keeps its default instead.
                if let value = effective.options[keyword], !(keyword == "connecttimeout" && value == "none") {
                    transport[keyword] = value
                }
            }
        }
        return AccessTarget(requested: item.requested, inventoryAlias: entry.alias, targetId: enrollment.targetId,
                            principal: enrollment.principal, hostname: entry.hostname, user: entry.user, port: entry.port,
                            hostKeys: entry.hostKeys ?? [], sshAlias: alias, transport: transport)
    }
}

// MARK: - Issuance

func issueAccess(_ arguments: AccessArguments, paths: AgentPaths, reporter: AccessReporter) throws {
    guard let ca = try CertificateAuthorityStore.load(from: paths) else {
        throw AccessFailure("not_enrolled", """
        no server is enrolled for temporary access on this Mac yet. Enroll each server once with: \
        \(tool) authorize HOST --temporary-access
        """)
    }
    let inventory = try InventoryStore.load(from: paths)
    let resolved = try resolveAccessTargets(arguments.hosts, inventory: inventory, ca: ca)
    try GrantDirectory.checkSocketPathLength(paths: paths)
    guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath().path else {
        throw AccessFailure("internal_error", "cannot find this executable")
    }
    try paths.ensureAccessDirectories()

    // One issuance at a time; status stays readable meanwhile.
    let lock: Int32
    do {
        lock = try FileLock.acquire(paths.accessLockFile, timeout: 2)
    } catch {
        throw AccessFailure("access_busy", """
        another access request is waiting for Touch ID approval or checking its servers. \
        Wait for it to finish, then run `\(tool) access status`.
        """)
    }
    defer { FileLock.release(lock) }

    let sweep = sweepGrants(paths: paths, stopExpired: true)
    if let live = sweep.kept.first {
        if let active = activeGrantDocument(live, paths: paths) {
            throw AccessFailure("access_already_active", """
            a grant is already active (\(live.grantId), until \(localTime(Date(timeIntervalSince1970: TimeInterval(live.manifest?.expiresAt ?? 0))))). \
            Reuse it if it covers the task (see `\(tool) access status`); to replace it, run `\(tool) access stop` first.
            """, details: ["active_grant": active])
        }
        throw AccessFailure("access_busy", "a previous grant (\(live.grantId)) is still starting or ending; try again in a minute.")
    }

    var grantId = AccessNames.newGrantId()
    let usedIds = Set(inventory.servers.compactMap { $0.temporaryAccess?.lastGrant?.grantId })
    while usedIds.contains(grantId) || FileManager.default.fileExists(atPath: GrantDirectory(paths: paths, grantId: grantId).url.path) {
        grantId = AccessNames.newGrantId()
    }
    let directory = GrantDirectory(paths: paths, grantId: grantId)
    let targets = try accessTargets(resolved, grantId: grantId)
    let request = AccessRequest(grantId: grantId, dataDirectory: paths.directory.path, caFingerprint: ca.fingerprint,
                                targets: targets, permissions: arguments.permissions,
                                requestedAt: UInt64(Date().timeIntervalSince1970), duration: arguments.duration)
    try request.validate()
    _ = try GrantSSHConfig.render(request, in: directory)
    let label = AccessLauncher.usesLaunchd ? AccessLauncher.label(paths: paths, grantId: grantId) : nil

    try directory.create()
    let requestData = try request.encoded()
    let digest = AccessRequest.digest(requestData)
    do {
        try SecureFile.writeAtomically(requestData, to: directory.request, mode: 0o600)
        try GrantManifest(request: request, launchLabel: label).write(to: directory)
    } catch {
        GrantStore.removeOwnedFiles(grantId: grantId, paths: paths)
        throw error
    }

    showSummary(request, reporter: reporter)

    let session = IssuanceSession(paths: paths, directory: directory, label: label, reporter: reporter)
    try session.run(request: request, executable: executable, digest: digest)
    reporter.progress("Temporary access is active until \(localTime(request.expiresAt)).")
    if let document = activeGrantDocument(GrantStore.inspect(name: grantId, paths: paths), paths: paths) {
        if reporter.json {
            reporter.emit(document)
        } else {
            printActiveGrant(document)
        }
    } else {
        throw AccessFailure("job_failed", "the grant ended right after it started; see `\(tool) access status`.")
    }
}

func showSummary(_ request: AccessRequest, reporter: AccessReporter) {
    let width = request.targets.map(\.inventoryAlias.count).max() ?? 0
    var lines = ["Temporary SSH access request", "  Targets (\(request.targets.count)):"]
    for target in request.targets {
        lines.append("    \(target.inventoryAlias.padding(toLength: width, withPad: " ", startingAt: 0))  \(target.user)@\(target.hostname):\(target.port)")
    }
    lines += [
        "  Duration:   \(AccessDuration.describe(request.duration)), until \(localTime(request.expiresAt)) (\(utc(request.expiresAt)))",
        "  Commands:   " + (request.permissions.forceCommand.map { "only `\($0)`" } ?? "any command the selected accounts allow"),
        "  PTY:        " + (request.permissions.pty ? "allowed" : "not allowed (--allow-pty enables it)"),
        "  Forwarding: none (agent, port and X11 forwarding and user rc are denied)",
        "",
        "One Touch ID approval on this Mac issues one certificate for all targets.",
        "Expiry and stop block new logins; sessions already open keep running.",
    ]
    reporter.progress(lines.joined(separator: "\n"))
}

/// Follows one grant job from launch to confirmation, and removes it again
/// when anything fails or the command is interrupted.
final class IssuanceSession {
    let paths: AgentPaths
    let directory: GrantDirectory
    let label: String?
    let reporter: AccessReporter
    private var connection: ControlConnection?
    private var childPid: pid_t?
    private var signalSources: [DispatchSourceSignal] = []

    init(paths: AgentPaths, directory: GrantDirectory, label: String?, reporter: AccessReporter) {
        self.paths = paths
        self.directory = directory
        self.label = label
        self.reporter = reporter
    }

    func run(request: AccessRequest, executable: String, digest: String) throws {
        // Interrupted (Ctrl-C, kill): withdraw the request instead of leaving it running.
        for signalNumber in [SIGINT, SIGTERM, SIGHUP] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: DispatchQueue.global())
            source.setEventHandler { [self] in
                abandon()
                reporter.fail(AccessFailure("cancelled", "the request was interrupted; no grant was issued."))
            }
            source.resume()
            signalSources.append(source)
        }
        defer {
            signalSources.forEach { $0.cancel() }
            for signalNumber in [SIGINT, SIGTERM, SIGHUP] { signal(signalNumber, SIG_DFL) }
        }

        do {
            childPid = try AccessLauncher.start(executable: executable, paths: paths, directory: directory, digest: digest,
                                                label: label ?? "")
        } catch {
            abandon()
            throw AccessFailure("job_failed", "could not start the grant job: \(error)")
        }
        guard let connection = ControlConnection.connect(directory.controlSocket.path, timeout: 15),
              connection.request(["op": "attach"], timeout: 10)?["event"] as? String == "attached" else {
            abandon()
            throw AccessFailure("job_failed", "the grant job did not start; see \(paths.displayPath(paths.directory))/access.stderr.log")
        }
        self.connection = connection

        let promptTimeout = TimeInterval(ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_PROMPT_TIMEOUT"] ?? "") ?? 60
        var issued: [String: Any]?
        while issued == nil {
            guard let message = connection.receive(timeout: promptTimeout + 60) else {
                abandon()
                throw AccessFailure("job_failed", "the grant job stopped answering; nothing was issued.")
            }
            switch message["event"] as? String {
            case "approval-requested":
                reporter.progress("Waiting for Touch ID approval on this Mac...")
            case "issued":
                issued = message
            case "failed":
                let code = message["code"] as? String ?? "job_failed"
                let text = message["message"] as? String ?? "the grant was not issued"
                finishFailed()
                throw AccessFailure(code, text + (code == "approval_denied" || code == "approval_timeout"
                    ? " Ask the user before requesting again." : ""))
            default:
                break
            }
        }

        reporter.progress("Approved. Checking a certificate login on each target (no command runs)...")
        let fingerprint = issued?["temporary_key_fingerprint"] as? String ?? ""
        let outcomes = checkTargets(request, fingerprint: fingerprint)
        let failures = outcomes.filter { $0.outcome != .ok }
        for item in outcomes {
            if case .failed(let reason) = item.outcome {
                reporter.progress("  ✗ \(item.target.inventoryAlias): \(reason)")
            } else {
                reporter.progress("  ✓ \(item.target.inventoryAlias)")
            }
        }
        guard failures.isEmpty else {
            connection.send(["op": "abort", "reason": "readiness-failed"])
            finishFailed()
            let details = failures.map { item -> [String: Any] in
                var reason = ""
                if case .failed(let text) = item.outcome { reason = text }
                return ["requested": item.target.requested, "inventory_alias": item.target.inventoryAlias, "reason": reason]
            }
            throw AccessFailure("readiness_failed", """
            \(failures.count) of \(request.targets.count) target\(request.targets.count == 1 ? "" : "s") did not accept the \
            certificate, so the grant was withdrawn: \(failures.map(\.target.inventoryAlias).joined(separator: ", ")). \
            Run `\(tool) audit` for them, or `\(tool) authorize HOST --temporary-access` again.
            """, details: ["failed_targets": details])
        }
        guard connection.request(["op": "confirm"], timeout: 10)?["event"] as? String == "active" else {
            abandon()
            throw AccessFailure("job_failed", "the grant job did not confirm activation; it was withdrawn.")
        }
        connection.close()
    }

    func checkTargets(_ request: AccessRequest, fingerprint: String) -> [(target: AccessTarget, outcome: CertificateLoginCheck.Outcome)] {
        var outcomes = [CertificateLoginCheck.Outcome](repeating: .failed("not checked"), count: request.targets.count)
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: request.targets.count) { index in
            let outcome = CertificateLoginCheck.run(configFile: directory.sshConfig, alias: request.targets[index].sshAlias,
                                                    keyFingerprint: fingerprint)
            lock.lock()
            outcomes[index] = outcome
            lock.unlock()
        }
        return Array(zip(request.targets, outcomes)).map { ($0.0, $0.1) }
    }

    /// The job reported failure: wait for it to exit and make sure nothing is left.
    private func finishFailed() {
        connection?.close()
        waitForJobExit(seconds: 10)
        cleanupLeftovers()
    }

    /// Withdraws a request whose job may still be running.
    func abandon() {
        connection?.close()
        waitForJobExit(seconds: 5)
        if let label { AccessLauncher.bootout(label: label) }
        if let pid = childPid, let manifest = GrantManifest.read(from: directory), manifest.process?.pid == pid,
           manifest.process?.isRunning == true {
            kill(pid, SIGTERM)
        }
        waitForJobExit(seconds: 5)
        cleanupLeftovers()
    }

    private func waitForJobExit(seconds: Double) {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            let running = GrantManifest.read(from: directory)?.process?.isRunning ?? false
            if !running && !FileManager.default.fileExists(atPath: directory.controlSocket.path) { return }
            if !running && GrantManifest.read(from: directory) == nil { return }
            usleep(100_000)
        }
    }

    private func cleanupLeftovers() {
        if let label { AccessLauncher.bootout(label: label) }
        if let pid = childPid { var status: Int32 = 0; waitpid(pid, &status, WNOHANG) }
        let inspection = GrantStore.inspect(name: directory.grantId, paths: paths)
        if inspection.problem == nil, !inspection.running {
            try? GrantStore.remove(inspection, paths: paths)
        }
    }
}

// MARK: - Status, stop and cleanup

/// The JSON description of a live, active grant, or nil.
func activeGrantDocument(_ inspection: GrantInspection, paths: AgentPaths) -> [String: Any]? {
    guard inspection.problem == nil, inspection.running, !inspection.expired else { return nil }
    let directory = GrantDirectory(paths: paths, grantId: inspection.grantId)
    guard let status = AccessControl.request(directory, ["op": "status"]), status["state"] as? String == "active",
          let request = GrantStore.readRequest(directory)?.request else { return nil }
    let remaining = (status["remaining_seconds"] as? NSNumber)?.intValue ?? max(0, Int(request.expiresAt.timeIntervalSinceNow))
    let issuedAt = Date(timeIntervalSince1970: TimeInterval(request.requestedAt))
    return [
        "ok": true,
        "status": "active",
        "grant_id": request.grantId,
        "issued_at": utc(issuedAt),
        "expires_at": utc(request.expiresAt),
        "expires_at_local": localTime(request.expiresAt),
        "remaining_seconds": remaining,
        "serial": status["serial"] ?? NSNull(),
        "permissions": [
            "force_command": request.permissions.forceCommand ?? NSNull(),
            "pty": request.permissions.pty,
            "forwarding": false,
        ] as [String: Any],
        "ssh_config_path": directory.sshConfig.path,
        "targets": request.targets.map { target -> [String: Any] in
            [
                "requested": target.requested,
                "inventory_alias": target.inventoryAlias,
                "hostname": target.hostname,
                "user": target.user,
                "port": target.port,
                "ssh_alias": target.sshAlias,
                "ssh_argv": GrantSSHConfig.argv(target, in: directory),
            ]
        },
    ]
}

func printActiveGrant(_ document: [String: Any]) {
    let grantId = document["grant_id"] as? String ?? ""
    let local = document["expires_at_local"] as? String ?? ""
    let remaining = (document["remaining_seconds"] as? Int).map { AccessDuration.describe(UInt64(max(0, $0))) } ?? ""
    var lines = ["Temporary access \(grantId) is active until \(local) (\(remaining) left).", "Connect with:"]
    for target in document["targets"] as? [[String: Any]] ?? [] {
        let argv = (target["ssh_argv"] as? [String] ?? []).map(Terminal.shellQuoted).joined(separator: " ")
        lines.append("  \(argv) [COMMAND]")
    }
    lines.append("Stop early with `\(tool) access stop`.")
    Out.say(lines.joined(separator: "\n"))
}

func accessStatus(paths: AgentPaths, reporter: AccessReporter) {
    let inspections = GrantStore.inspectAll(paths: paths)
    for inspection in inspections {
        if let active = activeGrantDocument(inspection, paths: paths) {
            var document = active
            document["stale_grants"] = staleList(inspections, excluding: inspection.grantId, paths: paths)
            if reporter.json { reporter.emit(document) } else { printActiveGrant(document) }
            return
        }
    }
    let stale = staleList(inspections, excluding: nil, paths: paths)
    let pending = inspections.first { $0.problem == nil && $0.running && !$0.expired }
    var document: [String: Any] = ["ok": true, "status": pending == nil ? "inactive" : "pending", "stale_grants": stale]
    if let pending {
        let directory = GrantDirectory(paths: paths, grantId: pending.grantId)
        document["grant_id"] = pending.grantId
        document["state"] = AccessControl.request(directory, ["op": "status"])?["state"] as? String ?? "unknown"
    }
    document["cleanup_suggested"] = !stale.isEmpty
    if reporter.json {
        reporter.emit(document)
        return
    }
    if let pending {
        Out.say("A grant (\(pending.grantId)) is being requested or checked; it is not usable yet.")
    } else {
        Out.say("No temporary access is active. Request it with `\(tool) access HOST[,HOST...] --for DURATION`.")
    }
    if !stale.isEmpty {
        Out.say("\(stale.count) leftover grant director\(stale.count == 1 ? "y" : "ies"); remove them with `\(tool) access cleanup`.")
    }
}

func staleList(_ inspections: [GrantInspection], excluding: String?, paths: AgentPaths) -> [[String: Any]] {
    inspections.compactMap { inspection in
        guard inspection.grantId != excluding else { return nil }
        if let problem = inspection.problem { return ["grant_id": inspection.grantId, "reason": problem] }
        if inspection.running && !inspection.expired { return nil }
        if inspection.manifest?.process == nil, let created = inspection.manifest?.createdAt,
           Date().timeIntervalSince1970 - TimeInterval(created) < 120 {
            return nil // a request that is still starting
        }
        return ["grant_id": inspection.grantId, "reason": inspection.running ? "expired but its job still runs" : "its job is no longer running"]
    }
}

func accessStop(paths: AgentPaths, reporter: AccessReporter) throws {
    var stopped: [String] = []
    var problems: [[String: Any]] = []
    for inspection in GrantStore.inspectAll(paths: paths) where inspection.problem == nil && inspection.running {
        let directory = GrantDirectory(paths: paths, grantId: inspection.grantId)
        reporter.progress("Stopping grant \(inspection.grantId)...")
        if stopJob(inspection, paths: paths) {
            stopped.append(inspection.grantId)
        } else {
            problems.append(["grant_id": inspection.grantId, "reason": "the job did not stop"])
        }
        _ = directory
    }
    // Leftovers of stopped grants, under the lifecycle lock.
    try paths.ensureAccessDirectories()
    if let lock = try? FileLock.acquire(paths.accessLockFile, timeout: 15) {
        let sweep = sweepGrants(paths: paths, stopExpired: true)
        FileLock.release(lock)
        _ = sweep
    }
    guard problems.isEmpty else {
        throw AccessFailure("stop_failed", "could not stop \(problems.count) grant(s); try `\(tool) access cleanup`.",
                            details: ["stopped": stopped, "failed": problems])
    }
    if reporter.json {
        reporter.emit(["ok": true, "status": stopped.isEmpty ? "inactive" : "stopped", "stopped": stopped])
    } else {
        Out.say(stopped.isEmpty
            ? "No temporary access was active."
            : "Stopped \(stopped.joined(separator: ", ")). New logins with it fail now; sessions already open keep running.")
    }
}

/// Asks a running job to stop, then makes sure it exits (launchd bootout, or
/// SIGTERM to the verified process). Returns true once it is gone.
func stopJob(_ inspection: GrantInspection, paths: AgentPaths) -> Bool {
    let directory = GrantDirectory(paths: paths, grantId: inspection.grantId)
    guard let process = inspection.manifest?.process else { return true }
    _ = AccessControl.request(directory, ["op": "stop"])
    func gone(within seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if !process.isRunning { return true }
            usleep(100_000)
        }
        return !process.isRunning
    }
    if gone(within: 10) { return true }
    if let label = inspection.manifest?.launchLabel { AccessLauncher.bootout(label: label) }
    if process.isRunning { kill(process.pid, SIGTERM) }
    return gone(within: 5)
}

struct SweepResult {
    var removed: [String] = []
    var skipped: [(grantId: String, reason: String)] = []
    var kept: [GrantInspection] = []
}

/// Removes leftover grant directories. Caller holds the lifecycle lock.
/// Live, unexpired grants are kept; expired jobs are stopped first; anything
/// whose ownership or state is uncertain is skipped with a reason.
func sweepGrants(paths: AgentPaths, stopExpired: Bool) -> SweepResult {
    var result = SweepResult()
    for inspection in GrantStore.inspectAll(paths: paths) {
        if let problem = inspection.problem {
            result.skipped.append((inspection.grantId, problem))
            continue
        }
        if inspection.running {
            guard inspection.expired, stopExpired else {
                result.kept.append(inspection)
                continue
            }
            guard stopJob(inspection, paths: paths) else {
                result.skipped.append((inspection.grantId, "expired, but its job did not stop"))
                continue
            }
        }
        if let label = inspection.manifest?.launchLabel { AccessLauncher.bootout(label: label) }
        let fresh = GrantStore.inspect(name: inspection.grantId, paths: paths)
        guard fresh.problem == nil || !FileManager.default.fileExists(atPath: fresh.directory.path) else {
            result.skipped.append((inspection.grantId, fresh.problem ?? "changed during cleanup"))
            continue
        }
        if FileManager.default.fileExists(atPath: fresh.directory.path) {
            guard !fresh.running else {
                result.kept.append(fresh)
                continue
            }
            do {
                try GrantStore.remove(fresh, paths: paths)
            } catch {
                result.skipped.append((inspection.grantId, "\(error)"))
                continue
            }
        }
        result.removed.append(inspection.grantId)
    }
    // Jobs launchd still lists for this data directory but that left no directory.
    for job in AccessLauncher.loadedLabels(paths: paths) where !job.running {
        let grantId = String(job.label.split(separator: ".").last ?? "")
        if !FileManager.default.fileExists(atPath: GrantDirectory(paths: paths, grantId: grantId).url.path) {
            AccessLauncher.bootout(label: job.label)
        }
    }
    reconcileGrantRecords(paths: paths, live: Set(result.kept.map(\.grantId)))
    return result
}

/// Latest-grant records whose grant is gone get an end time and reason, so the
/// inventory never claims a grant that no longer exists.
func reconcileGrantRecords(paths: AgentPaths, live: Set<String>) {
    let inventory = (try? InventoryStore.load(from: paths)) ?? Inventory()
    let open = inventory.servers.contains { entry in
        guard let grant = entry.temporaryAccess?.lastGrant else { return false }
        return grant.endedAt == nil && !live.contains(grant.grantId)
    }
    guard open else { return }
    try? InventoryStore.update(paths) { inventory in
        for index in inventory.servers.indices {
            guard let grant = inventory.servers[index].temporaryAccess?.lastGrant, grant.endedAt == nil,
                  !live.contains(grant.grantId),
                  !FileManager.default.fileExists(atPath: GrantDirectory(paths: paths, grantId: grant.grantId).url.path) else { continue }
            inventory.servers[index].temporaryAccess?.lastGrant?.endedAt = .wholeSecondsNow
            inventory.servers[index].temporaryAccess?.lastGrant?.endReason = grant.expiresAt <= Date() ? "expired" : "abandoned"
        }
    }
}

func accessCleanup(paths: AgentPaths, reporter: AccessReporter) throws {
    try paths.ensureAccessDirectories()
    let lock: Int32
    do {
        lock = try FileLock.acquire(paths.accessLockFile, timeout: 5)
    } catch {
        throw AccessFailure("access_busy", "an access request is in progress; run cleanup again once it finishes.")
    }
    let result = sweepGrants(paths: paths, stopExpired: true)
    FileLock.release(lock)
    let kept = result.kept.map { ["grant_id": $0.grantId, "reason": "live grant, still valid"] }
    if reporter.json {
        reporter.emit([
            "ok": true,
            "status": "cleaned",
            "removed": result.removed.map { ["grant_id": $0] },
            "skipped": result.skipped.map { ["grant_id": $0.grantId, "reason": $0.reason] } + kept,
        ])
        return
    }
    Out.say(result.removed.isEmpty ? "Nothing to remove." : "Removed \(result.removed.count) leftover grant(s): \(result.removed.joined(separator: ", ")).")
    for item in result.skipped { Out.say("Skipped \(item.grantId): \(item.reason).") }
    for item in result.kept { Out.say("Kept \(item.grantId): live grant, still valid.") }
    Out.say("CA trust on the servers and the inventory are unchanged.")
}

// MARK: - Time

func utc(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.timeZone = TimeZone(identifier: "UTC")
    return formatter.string(from: date)
}

/// `2026-10-15 23:41:07 -0300 (America/Sao_Paulo)`.
func localTime(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
    return "\(formatter.string(from: date)) (\(TimeZone.current.identifier))"
}

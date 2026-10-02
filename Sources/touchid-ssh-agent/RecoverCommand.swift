import Darwin
import Foundation
import TouchIDSSHCore

/// What the plain-text part of an emergency kit says.
struct KitNotes {
    var emergencyFingerprint: String?
    var backupFile: String?

    init(kitText: String) {
        for line in kitText.split(whereSeparator: \.isNewline) {
            let text = line.trimmingCharacters(in: .whitespaces)
            if text.hasPrefix("Emergency key:") {
                emergencyFingerprint = text.dropFirst("Emergency key:".count)
                    .trimmingCharacters(in: .whitespaces).split(separator: " ").first.map(String.init)
            } else if text.hasPrefix("Inventory backup:") {
                let value = text.dropFirst("Inventory backup:".count).trimmingCharacters(in: .whitespaces)
                if !value.hasPrefix("none") { backupFile = value }
            }
        }
    }
}

struct RecoverOptions {
    var kit: URL
    var inventory: String?
    var configFile: String?
    var keepEmergencyKey = false

    init(_ arguments: ArraySlice<String>, command: String) throws {
        let usage = "usage: \(tool) \(command) emergency-kit.txt [--inventory FILE] [-F SSH_CONFIG]"
            + (command == "recover" ? " [--keep-emergency-key]" : "")
        var kitPath: String?
        var iterator = arguments.makeIterator()
        while let argument = iterator.next() {
            switch argument {
            case "--inventory":
                guard let value = iterator.next() else { throw UsageError(description: usage) }
                inventory = value
            case "-F":
                guard let value = iterator.next() else { throw UsageError(description: usage) }
                configFile = (value as NSString).expandingTildeInPath
            case "--keep-emergency-key" where command == "recover":
                keepEmergencyKey = true
            default:
                guard kitPath == nil, !argument.hasPrefix("-") else { throw UsageError(description: usage) }
                kitPath = argument
            }
        }
        guard let kitPath else { throw UsageError(description: usage) }
        kit = URL(fileURLWithPath: (kitPath as NSString).expandingTildeInPath)
    }
}

/// `recover` moves every inventory server to this Mac; `recovery test` (dryRun)
/// only checks that the emergency kit still logs in everywhere.
func recover(_ arguments: ArraySlice<String>, paths: AgentPaths, dryRun: Bool) throws {
    let command = dryRun ? "recovery test" : "recover"
    let options = try RecoverOptions(arguments, command: command)
    try Terminal.requireInteractive(command)
    guard let kitData = FileManager.default.contents(atPath: options.kit.path) else {
        throw UsageError(description: "cannot read the emergency kit at \(options.kit.path)")
    }
    guard let age = Command.find("age") else {
        throw UsageError(description: "age is not installed. Run `make install` or `brew install age`.")
    }
    let notes = KitNotes(kitText: String(decoding: kitData, as: UTF8.self))
    let steps = dryRun ? 3 : 6

    Out.header(command, dryRun ? "check the emergency kit; nothing changes" : "move your servers to this Mac")
    Out.say("""
    You will be asked for your emergency passphrase twice, for security: first
    by age, to open the inventory, then by ssh-add, to load the emergency key.
    Each tool asks for it itself, so this program never sees the passphrase.
    """)

    // 1. Open the inventory with the kit.
    Out.section("1/\(steps) Opening the inventory")
    let inventoryFile = try locateInventory(options: options, notes: notes, paths: paths)
    Out.say("  \(paths.displayPath(inventoryFile))")
    let decrypted = try Command.runAttachedToTerminal(age, ["-d", "-i", options.kit.path, inventoryFile.path], stdin: Data())
    guard decrypted.succeeded, let old = try? Inventory.decode(decrypted.stdout) else {
        throw UsageError(description: "could not open the inventory with this kit (wrong passphrase, or a backup from another kit).")
    }
    guard !old.servers.isEmpty else { throw UsageError(description: "the inventory lists no servers.") }
    Out.say("  \(old.servers.count) server\(old.servers.count == 1 ? "" : "s"), recorded by \(old.mac):")
    for entry in old.servers {
        Out.say("    • \(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
    }

    if dryRun {
        try testEmergencyLogins(old, kitData: kitData, notes: notes, options: options, paths: paths)
        return
    }

    // 2. This Mac's Touch ID key, and the agent that uses it.
    Out.section("2/\(steps) Touch ID key on this Mac")
    let identity = try IdentityStore.load(from: paths) ?? {
        let created = try IdentityStore.create(in: paths, policy: .currentSet)
        Out.say("  Created in the Secure Enclave: \(created.fingerprint)")
        return created
    }()
    if old.servers.contains(where: { $0.loginKeyFingerprint == identity.fingerprint }) {
        throw UsageError(description: """
        this Mac's Touch ID key (\(identity.fingerprint)) is the one the inventory lists,
        so recovering would remove the key this Mac is using. If it stopped working
        (for example, fingerprints changed), delete it first with `\(tool) delete`.
        """)
    }
    Out.say("  \(identity.fingerprint)")
    try ensureAgentRunning(paths: paths)

    // 3. A fresh emergency key: the one in this kit is about to be used.
    Out.section("3/\(steps) Emergency kit")
    let oldEmergency = notes.emergencyFingerprint ?? old.servers.first?.recoveryKeyFingerprint
    try adoptBackupFolder(of: inventoryFile, paths: paths)
    var current = try RecoveryStore.load(from: paths)
    if current == nil || (current?.fingerprint == oldEmergency && !options.keepEmergencyKey) {
        Out.say("  Once used, an emergency key counts as exposed, so a new kit replaces it.\n")
        try createEmergencyKit(paths: paths, replace: current != nil, ownPassphrase: false)
        current = try RecoveryStore.load(from: paths)
    } else {
        Out.say("  Using the emergency key already configured on this Mac: \(current!.fingerprint)")
    }
    guard let newEmergency = current else {
        throw UsageError(description: "no new emergency key was configured, so nothing was changed.")
    }
    let rotating = newEmergency.fingerprint != oldEmergency

    // 4. Every server: add the new keys, check Touch ID, remove the old keys.
    Out.section("4/\(steps) Moving the servers")
    Out.say("""
    For each server: add this Mac's keys, check the Touch ID login (one Touch ID),
    then remove the lost Mac's key\(rotating ? " and the old emergency key" : "").
    """)
    guard Terminal.confirm(word: "RECOVER", cancelWord: "ABORT",
                           prompt: "Type RECOVER to update \(old.servers.count) server\(old.servers.count == 1 ? "" : "s") (or ABORT): ") else {
        Out.say("Aborted. No server was changed.")
        return
    }
    let agent = try EmergencyAgent()
    defer { agent.stop() }
    let loaded = try agent.load(kit: kitData)
    if let oldEmergency, loaded.fingerprint != oldEmergency {
        Out.say("  ! The kit's key (\(loaded.fingerprint)) is not the one the kit's notes name (\(oldEmergency)).")
    }

    var results: [(entry: InventoryEntry, ok: Bool, text: String)] = []
    let alreadyHere = try InventoryStore.load(from: paths).servers
    for entry in old.servers {
        Out.say("\n\(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
        // A previous run already moved this server: running again is safe.
        if let moved = alreadyHere.first(where: {
            $0.hostname == entry.hostname && $0.port == entry.port && $0.user == entry.user
                && $0.loginKeyFingerprint == identity.fingerprint
        }) {
            Out.say("  ✓ already moved to this Mac by an earlier run; skipped")
            results.append((moved, true, "already moved"))
            continue
        }
        let result = recoverServer(entry, configFile: options.configFile, agent: agent,
                                   oldEmergency: rotating ? loaded.fingerprint : nil,
                                   identity: identity, newEmergency: newEmergency, paths: paths)
        Out.say("  \(result.ok ? "✓" : "✗") \(result.text)")
        results.append(result)
    }
    agent.stop()

    var inventory = try InventoryStore.load(from: paths)
    inventory.mac = IdentityStore.defaultComment()
    for result in results where result.ok { inventory.upsert(result.entry) }
    try InventoryStore.save(inventory, to: paths)
    let failed = results.filter { !$0.ok }
    if failed.isEmpty {
        preserveOldBackup(inventoryFile, paths: paths)
        reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    } else {
        // The old backup stays as it is, so the old kit can open it for another run.
        Out.say("\nThe backup in the cloud folder was left unchanged, so the old kit can open it again.")
    }

    // 5. ssh config, so `ssh NAME` works on this Mac.
    Out.section("5/\(steps) ssh config")
    var recovered = results.filter(\.ok).map(\.entry)
    for (index, entry) in recovered.enumerated() where !sshConfigStatus(for: entry, paths: paths).ok {
        Out.say("\n\(entry.alias)")
        guard let resolved = try? RemoteKeys.resolve(SSHTarget(destination: entry.destination, port: entry.port,
                                                                configFile: entry.sshConfigFile)),
              let name = try offerSSHConfig(destination: entry.destination, suggestedName: entry.alias,
                                            resolved: resolved, configFile: options.configFile, paths: paths) else { continue }
        inventory.servers.removeAll { $0.alias == entry.alias }
        recovered[index].alias = name
        recovered[index].destination = name
        inventory.upsert(recovered[index])
    }
    try InventoryStore.save(inventory, to: paths)

    // 6. Show the result.
    Out.section("6/\(steps) Audit")
    if recovered.isEmpty {
        Out.say("  Nothing to audit: no server was moved.")
    } else {
        try runAudit(aliases: Set(recovered.map(\.alias)), paths: paths)
    }

    if failed.isEmpty {
        Out.say("""

        All servers now trust this Mac. \(rotating ? "The old emergency kit was removed from every server: you can destroy it." : "")
        """)
    } else {
        Out.say("""

        \(failed.count) server\(failed.count == 1 ? " was" : "s were") not recovered: \(failed.map(\.entry.alias).joined(separator: ", ")).
        Keep the old emergency kit until they are fixed: it still opens them. Then run
        recover again; servers already moved to this Mac are skipped.
        """)
        exit(1)
    }
}

/// Moves one server to this Mac. The old keys are removed only after the new
/// Touch ID key logged in, and only lines whose fingerprint is exactly the
/// lost Mac's key (or the used emergency key) are touched.
func recoverServer(_ entry: InventoryEntry, configFile: String?, agent: EmergencyAgent, oldEmergency: String?,
                   identity: StoredIdentity, newEmergency: RecoveryKey,
                   paths: AgentPaths) -> (entry: InventoryEntry, ok: Bool, text: String) {
    var failedEntry = entry
    func fail(_ text: String) -> (entry: InventoryEntry, ok: Bool, text: String) {
        failedEntry.lastAudit = .wholeSecondsNow
        failedEntry.lastAuditResult = "recovery failed: \(text)"
        return (failedEntry, false, text)
    }
    let target = SSHTarget(destination: "\(entry.user)@\(entry.hostname)", port: entry.port, configFile: configFile)
    guard let resolved = try? RemoteKeys.resolve(target) else { return fail("ssh could not resolve the server") }

    let policy: KnownHostsPolicy
    if let keys = entry.hostKeys, !keys.isEmpty, let pinned = try? KnownHostsPolicy.pinned(keys, for: resolved, in: agent.directory) {
        policy = pinned
        Out.say("  host key checked against the inventory")
    } else {
        policy = .acceptNew(nil)
        Out.say("  ! no host key recorded for this server: trusting the one it presents now")
    }

    let newKeys = [AuthorizedKey.login(identity), AuthorizedKey.recovery(newEmergency)]
    let added = RemoteKeys.emergencySession(target, agent: agent, knownHosts: policy,
                                            script: RemoteKeys.installScript(newKeys) + RemoteKeys.listing)
    guard added.ok else { return fail("the emergency key could not log in: \(added.error)") }
    let report = RemoteKeys.parse(added.output)
    Out.say("  Touch ID key \(report["login"] == "added" ? "added" : "already there"), "
        + "emergency key \(report["recovery"] == "added" ? "added" : "already there")")
    if case .pinned = policy, let keys = entry.hostKeys { try? HostKeys.remember(keys, for: resolved) }

    Out.say("  Checking the Touch ID login (approve the Touch ID prompt)...")
    let check = RemoteKeys.verifyLogin(on: target, paths: paths, identity: identity)
    guard check == .ok else { return fail("old keys kept, because the new Touch ID key did not log in: \(describe(check))") }

    // Never remove this Mac's keys, whatever the fingerprints say.
    let protected: Set<Data> = [identity.publicKeyBlob, newEmergency.blob]
    let retired = Set([entry.loginKeyFingerprint] + (oldEmergency.map { [$0] } ?? []))
    var seen = Set<Data>()
    let doomed = RemoteKeys.listedLines(added.output)
        .compactMap { RemoteKeys.keyBlob(inAuthorizedKeysLine: $0) }
        .filter { retired.contains(SSHKeyFormat.fingerprint(blob: $0)) && !protected.contains($0) && seen.insert($0).inserted }
    if !doomed.isEmpty {
        let removed = RemoteKeys.emergencySession(target, agent: agent, knownHosts: policy, script: RemoteKeys.removeScript(doomed))
        let remaining = RemoteKeys.listedLines(removed.output).compactMap { RemoteKeys.keyBlob(inAuthorizedKeysLine: $0) }
        guard removed.ok, !remaining.contains(where: doomed.contains),
              remaining.contains(identity.publicKeyBlob), remaining.contains(newEmergency.blob) else {
            return fail("the new keys work, but the old keys could not be removed: \(removed.error)")
        }
    }

    var updated = entry
    if let alias = try? RemoteKeys.resolve(SSHTarget(destination: entry.alias, configFile: configFile)),
       alias.hostname == entry.hostname, alias.port == entry.port {
        updated.destination = entry.alias
    } else {
        updated.destination = "\(entry.user)@\(entry.hostname)"
    }
    updated.sshConfigFile = configFile
    updated.loginKeyFingerprint = identity.fingerprint
    updated.recoveryKeyFingerprint = newEmergency.fingerprint
    updated.authorizedAt = .wholeSecondsNow
    let trusted = HostKeys.known(for: resolved)
    if !trusted.isEmpty { updated.hostKeys = trusted }
    updated.lastAudit = .wholeSecondsNow
    updated.lastAuditResult = "recovered"
    let removedText = doomed.isEmpty ? "no old key was left to remove" : "removed \(doomed.count) old key\(doomed.count == 1 ? "" : "s")"
    return (updated, true, "moved to this Mac; \(removedText)")
}

/// `recovery test`: logs in to every server with the emergency key only.
func testEmergencyLogins(_ inventory: Inventory, kitData: Data, notes: KitNotes, options: RecoverOptions, paths: AgentPaths) throws {
    Out.section("2/3 Loading the emergency key")
    let agent = try EmergencyAgent()
    defer { agent.stop() }
    let loaded = try agent.load(kit: kitData)
    Out.say("  \(loaded.fingerprint)")

    Out.section("3/3 Logging in with the emergency key only")
    var failures = 0
    for entry in inventory.servers {
        let target = SSHTarget(destination: "\(entry.user)@\(entry.hostname)", port: entry.port, configFile: options.configFile)
        let resolved = try? RemoteKeys.resolve(target)
        let policy: KnownHostsPolicy
        if let resolved, let keys = entry.hostKeys, !keys.isEmpty,
           let pinned = try? KnownHostsPolicy.pinned(keys, for: resolved, in: agent.directory) {
            policy = pinned
        } else {
            // Nothing on this Mac changes: unknown host keys go to a scratch file.
            policy = .acceptNew(agent.directory.appendingPathComponent("known_hosts-test"))
        }
        let session = RemoteKeys.emergencySession(target, agent: agent, knownHosts: policy, script: nil)
        Out.say("  \(session.ok ? "✓" : "✗") \(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))"
            + (session.ok ? "" : ": \(session.error)"))
        if !session.ok { failures += 1 }
    }
    Out.say(failures == 0
        ? "\nThe emergency kit opens every server in the inventory. Nothing was changed."
        : "\n\(failures) server\(failures == 1 ? "" : "s") did not accept the emergency key. Run `\(tool) authorize` for them.")
    if failures > 0 { exit(1) }
}

/// Finds inventory.age: --inventory, the folder named in the kit, this Mac's
/// backup folder, or a path the user types.
func locateInventory(options: RecoverOptions, notes: KitNotes, paths: AgentPaths) throws -> URL {
    var candidates: [String] = []
    if let explicit = options.inventory { candidates.append(explicit) }
    if let fromKit = notes.backupFile { candidates.append(fromKit) }
    if let folder = SettingsStore.load(from: paths).backupDirectory {
        candidates.append(folder.appendingPathComponent(InventoryBackup.fileName).path)
    }
    for candidate in candidates {
        let url = URL(fileURLWithPath: (candidate as NSString).expandingTildeInPath)
        if FileManager.default.fileExists(atPath: url.path) { return url }
    }
    Out.say("  The inventory backup was not found\(notes.backupFile.map { " at \($0)" } ?? "").")
    Out.say("  Download inventory.age from your cloud folder, or point to its folder.")
    while let answer = Terminal.ask("Path to inventory.age (or its folder): ") {
        var url = URL(fileURLWithPath: (answer.trimmingCharacters(in: .whitespaces) as NSString).expandingTildeInPath)
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue {
            url = url.appendingPathComponent(InventoryBackup.fileName)
        }
        if FileManager.default.fileExists(atPath: url.path) { return url }
        Out.say("  Not found: \(url.path)")
    }
    throw UsageError(description: "no inventory backup, so nothing was changed.")
}

/// On a new Mac without a backup folder, offers the folder the old backup came from.
func adoptBackupFolder(of inventoryFile: URL, paths: AgentPaths) throws {
    var settings = SettingsStore.load(from: paths)
    guard settings.backupDirectory == nil else { return }
    let folder = inventoryFile.deletingLastPathComponent()
    let answer = Terminal.ask("Use \(paths.displayPath(folder)) as this Mac's backup folder? [Y/n]: ") ?? "n"
    guard !answer.lowercased().hasPrefix("n") else {
        Out.say("  No backup folder. Set one later with `\(tool) set backup-path DIR`.")
        return
    }
    settings.backupPath = folder.path
    try SettingsStore.save(settings, to: paths)
    Out.say("  Backup folder: \(paths.displayPath(folder))")
}

/// Keeps the pre-recovery backup (still readable with the old kit) next to the new one.
func preserveOldBackup(_ inventoryFile: URL, paths: AgentPaths) {
    guard let folder = SettingsStore.load(from: paths).backupDirectory,
          inventoryFile.deletingLastPathComponent().standardizedFileURL == folder.standardizedFileURL else { return }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd-HHmm"
    let copy = folder.appendingPathComponent("inventory-before-recovery-\(formatter.string(from: Date())).age")
    if (try? FileManager.default.copyItem(at: inventoryFile, to: copy)) != nil {
        Out.say("\nThe previous backup was kept as \(paths.displayPath(copy)) (it opens with the old kit).")
    }
}

/// recover checks the Touch ID login on every server, so the agent must run.
func ensureAgentRunning(paths: AgentPaths) throws {
    guard !AgentClient.isListening(socketPath: paths.socket.path) else { return }
    guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath().path,
          !executable.contains("/.build/") else {
        throw UsageError(description: "the agent is not running. Run `\(tool) install` first.")
    }
    Out.say("  Starting the agent (LaunchAgent \(LaunchAgent.label))...")
    try LaunchAgent.install(executable: executable, paths: paths)
    for _ in 0..<30 where !AgentClient.isListening(socketPath: paths.socket.path) { usleep(100_000) }
    guard AgentClient.isListening(socketPath: paths.socket.path) else {
        throw UsageError(description: "the agent did not start. See \(paths.displayPath(paths.directory))/agent.stderr.log")
    }
}

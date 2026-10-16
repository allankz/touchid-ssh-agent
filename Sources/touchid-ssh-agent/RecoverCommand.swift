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
///
/// The kit's passphrase is asked first (by age, then by ssh-add) and never
/// again. Everything is checked before the user chooses whether to replace the
/// emergency key, and no server changes until they type RECOVER.
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
    let steps = dryRun ? 2 : 6

    Out.header(command, dryRun ? "check the emergency kit; nothing changes" : "move your servers to this Mac")
    Out.say("""
    You will be asked for this kit's passphrase twice, one right after the
    other, for security: age asks for it to open the inventory, then ssh-add
    asks again to load the emergency key. Each tool reads it itself, so this
    program never sees it, and it is not asked again after that.
    """ + (dryRun ? "" : "\n\nEverything is checked first. No server changes until you type RECOVER."))

    // 1. The kit's passphrase, twice and only here: the inventory, then the key.
    Out.section("1/\(steps) Opening the kit")
    let inventoryFile = try locateInventory(options: options, notes: notes, paths: paths)
    Out.say("  Inventory: \(paths.displayPath(inventoryFile))")
    Out.say("\n  age asks for this kit's passphrase:")
    let decrypted = try Command.runAttachedToTerminal(age, ["-d", "-i", options.kit.path, inventoryFile.path], stdin: Data())
    guard decrypted.succeeded, let old = try? Inventory.decode(decrypted.stdout) else {
        throw UsageError(description: "could not open the inventory with this kit (wrong passphrase, or a backup from another kit).")
    }
    guard !old.servers.isEmpty else { throw UsageError(description: "the inventory lists no servers.") }
    Out.say("  \(old.servers.count) server\(old.servers.count == 1 ? "" : "s"), recorded by \(old.mac):")
    for entry in old.servers {
        Out.say("    • \(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
    }
    let existing = try IdentityStore.load(from: paths)
    if !dryRun { try refuseKeysInUse(old, identity: existing, paths: paths) }

    let agent = try EmergencyAgent()
    defer { agent.stop() }
    Out.say("\n  ssh-add asks for the same passphrase again:")
    // An hour: on a recovery the user may create a new kit before the logins.
    let loaded = try agent.load(kit: kitData, lifetimeSeconds: 3600)
    Out.say("  Emergency key loaded: \(loaded.fingerprint). The passphrase is not asked again.")
    if let noted = notes.emergencyFingerprint, noted != loaded.fingerprint {
        Out.say("  ! The kit's key is not the one the kit's notes name (\(noted)).")
    }

    if dryRun {
        Out.section("2/2 Logging in with the emergency key only")
        let failures = emergencyLogins(old, agent: agent, configFile: options.configFile).filter { !$0 }.count
        Out.say(failures == 0
            ? "\nThe emergency kit opens every server in the inventory. Nothing was changed."
            : "\n\(failures) server\(failures == 1 ? "" : "s") did not accept the emergency key. Run `\(tool) authorize` for them.")
        if failures > 0 { exit(1) }
        return
    }

    // 2. This Mac and the servers, before anything changes on them.
    Out.section("2/\(steps) Checking")
    let identity = try existing ?? {
        let created = try IdentityStore.create(in: paths, policy: .currentSet)
        Out.say("  Touch ID key created in the Secure Enclave: \(created.fingerprint)")
        return created
    }()
    if existing != nil { Out.say("  Touch ID key: \(identity.fingerprint)") }
    try ensureAgentRunning(paths: paths)
    try adoptBackupFolder(of: inventoryFile, paths: paths)
    // Servers enrolled for temporary access trust the lost Mac's CA: this Mac's
    // CA (created once, reused by a resumed run) replaces it on each of them.
    let enrolled = old.servers.filter { $0.temporaryAccess != nil }
    var caPlan: RecoveryCA?
    if !enrolled.isEmpty {
        let ca: StoredIdentity, created: Bool
        do {
            (ca, created) = try CertificateAuthorityStore.loadOrCreate(in: paths)
        } catch {
            throw UsageError(description: """
            could not create this Mac's temporary-access CA (\(error)), which the \(enrolled.count) server\(enrolled.count == 1 ? "" : "s")
            enrolled for temporary access need. No server was changed. Check `\(tool) status` (Touch ID must have
            fingerprints enrolled) and run recover again.
            """)
        }
        caPlan = RecoveryCA(paths: paths, created: created, ca: ca)
        Out.say("  Temporary-access CA: \(ca.fingerprint)\(created ? " (created in the Secure Enclave)" : "")")
        Out.say("  \(enrolled.count) server\(enrolled.count == 1 ? " trusts" : "s trust") the lost Mac's CA for temporary access.")
    }
    Out.say("\n  Logging in with the emergency key only (nothing changes):")
    let reachable = emergencyLogins(old, agent: agent, configFile: options.configFile)
    let alreadyHere = try InventoryStore.load(from: paths).servers
    /// This Mac's record of the same server, preferring one that already lists this Mac's key.
    func local(_ entry: InventoryEntry) -> InventoryEntry? {
        let matches = alreadyHere.filter { $0.isSameServer(as: entry) }
        return matches.first { $0.loginKeyFingerprint == identity.fingerprint } ?? matches.first
    }
    func caPending(_ entry: InventoryEntry) -> Bool {
        guard entry.temporaryAccess != nil, let caPlan else { return false }
        return !caPlan.isComplete(local(entry), old: entry)
    }
    // When an earlier run already installed this Mac's login key on a server
    // (and may have removed the kit's key there), it is reached with the
    // Touch ID key instead of the kit.
    func resumable(_ entry: InventoryEntry) -> Bool {
        guard let local = local(entry) else { return false }
        let started: Set<CARotation.Step> = [.replacementAdded, .replacementVerified, .retirementStarted]
        return local.loginKeyFingerprint == identity.fingerprint || local.temporaryAccess?.caRotation.map { started.contains($0.step) } == true
    }
    let workable = zip(old.servers, reachable).map { $1 || resumable($0) }
    let unreachable = workable.filter { !$0 }.count
    guard unreachable < old.servers.count else {
        throw UsageError(description: "no server accepted this kit's key, so no server was changed.")
    }
    if unreachable > 0 {
        Out.say("\n  \(unreachable) server\(unreachable == 1 ? "" : "s") did not accept this kit's key and will be left as \(unreachable == 1 ? "it is" : "they are").")
    }

    // 3. Keep the kit's emergency key, or replace it with a new kit.
    Out.section("3/\(steps) Emergency key")
    let newEmergency: RecoveryKey
    let rotating: Bool
    let configured = try RecoveryStore.load(from: paths)
    // Compared by fingerprint: the same key may carry another comment.
    if let configured, configured.fingerprint != loaded.fingerprint {
        // From setup, or from an earlier recover run that replaced the key.
        if options.keepEmergencyKey {
            throw UsageError(description: """
            this Mac already has its own emergency key (\(configured.fingerprint)),
            so --keep-emergency-key cannot keep the kit's key. Run recover without it.
            """)
        }
        Out.say("""
          This Mac already has its own emergency key: \(configured.fingerprint).
          The servers get it, and this kit's key is removed from them.
        """)
        newEmergency = configured
        rotating = true
    } else if try options.keepEmergencyKey || !askReplaceEmergencyKey(loaded) {
        if configured == nil { try RecoveryStore.install(loaded, in: paths, replace: false) }
        Out.say("  Keeping this kit's emergency key: \(loaded.fingerprint). This kit stays your emergency kit.")
        newEmergency = loaded
        rotating = false
    } else {
        Out.say("""

          This kit is already loaded, so its passphrase is not asked again: the
          servers are updated with it. The passphrase shown next is for the NEW kit.

        """)
        try createEmergencyKit(paths: paths, replace: configured != nil, ownPassphrase: false, duringRecovery: true)
        guard let created = try RecoveryStore.load(from: paths), created.fingerprint != loaded.fingerprint else {
            throw UsageError(description: "no new emergency kit was saved, so no server was changed. Run recover again.")
        }
        Out.say("\n  The servers get the new emergency key, and this kit's key is removed from them.")
        newEmergency = created
        rotating = true
    }

    // 4. Every server: add the new keys, check Touch ID, remove the old keys.
    Out.section("4/\(steps) Moving the servers")
    Out.say("""
    For each server: add this Mac's keys, check the Touch ID login (one Touch ID),
    then remove the lost Mac's key\(rotating ? " and this kit's emergency key" : "").
    """)
    if !enrolled.isEmpty {
        Out.say("""

        On the \(enrolled.count) server\(enrolled.count == 1 ? "" : "s") with temporary access, this Mac's CA is added with the same
        principal and restrictions and checked with a certificate login (one more Touch ID,
        once, for a validation certificate that grants nothing). Once the new Touch ID login
        works, the lost Mac's CA is removed too: only that Mac could use it. If the new CA
        cannot be confirmed, temporary access there waits for `\(tool) authorize HOST --temporary-access`.
        Old temporary grants and their aliases are not restored.
        """)
    }
    let toMove = workable.filter { $0 }.count
    guard Terminal.confirm(word: "RECOVER", cancelWord: "ABORT",
                           prompt: "Type RECOVER to update \(toMove) server\(toMove == 1 ? "" : "s") (or ABORT): ") else {
        Out.say("Aborted. No server was changed.")
        return
    }

    // A dated copy of the backup this kit opens, before anything changes: a
    // later command on this Mac may rewrite inventory.age for the new key.
    let preserved = preserveOldBackup(inventoryFile, paths: paths)
    // Before any server changes: which old CAs each enrolled server must lose.
    try caPlan?.recordIntent(for: enrolled.filter(caPending))

    var results: [(entry: InventoryEntry, ok: Bool, text: String)] = []
    for (entry, accepted) in zip(old.servers, reachable) {
        Out.say("\n\(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
        let here = local(entry)
        let pendingCA = caPending(entry)
        // A previous run already moved this server: running again is safe. Its
        // CA work must be finished too; matching login keys alone are not enough.
        if let moved = here, moved.loginKeyFingerprint == identity.fingerprint,
           moved.recoveryKeyFingerprint == newEmergency.fingerprint, !pendingCA {
            Out.say("  ✓ already moved to this Mac by an earlier run; skipped")
            results.append((moved, true, "already moved"))
            continue
        }
        let viaTouchID = !accepted && resumable(entry)
        guard accepted || viaTouchID else {
            Out.say("  ✗ skipped: it did not accept this kit's key during the check")
            results.append((entry, false, "did not accept the emergency key"))
            continue
        }
        if viaTouchID {
            Out.say("  an earlier run already installed this Mac's key here; finishing through the Touch ID key")
        }
        let result = recoverServer(entry, local: here, configFile: options.configFile, agent: agent, viaTouchID: viaTouchID,
                                   oldEmergency: rotating ? loaded.fingerprint : nil,
                                   identity: identity, newEmergency: newEmergency,
                                   caPlan: pendingCA ? caPlan : nil, paths: paths)
        Out.say("  \(result.ok ? "✓" : "✗") \(result.text)")
        // Saved right away, so an interruption never forgets a server that moved.
        let saved = try InventoryStore.update(paths) { inventory -> InventoryEntry in
            inventory.mac = IdentityStore.defaultComment()
            inventory.updatedAt = .wholeSecondsNow
            guard result.ok else {
                // A pending CA record stays, with the reason.
                for index in inventory.servers.indices
                where inventory.servers[index].isSameServer(as: result.entry) && result.entry.temporaryAccess != nil {
                    inventory.servers[index].lastAudit = .wholeSecondsNow
                    inventory.servers[index].lastAuditResult = result.entry.lastAuditResult
                }
                return result.entry
            }
            var moved = result.entry
            inventory.servers.removeAll { $0.isSameServer(as: moved) }
            moved.alias = inventory.uniqueAlias(moved.alias, for: moved)
            inventory.servers.append(moved)
            return moved
        }
        results.append((saved, result.ok, result.text))
    }
    caPlan?.stop()
    agent.stop()

    let failed = results.filter { !$0.ok }
    if failed.isEmpty {
        reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    } else {
        // The old backup stays as it is, so the old kit can open it for another run.
        Out.say("\nThe backup in the cloud folder was left unchanged, so the old kit can open it again."
            + (preserved.map { " A copy is kept as \(paths.displayPath($0)): if a later command on this Mac rewrites the backup, run recover again with --inventory pointing to that copy." } ?? ""))
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
        recovered[index].alias = name
        recovered[index].destination = name
        let renamed = recovered[index]
        try InventoryStore.update(paths) { inventory in
            inventory.servers.removeAll { $0.alias == entry.alias }
            inventory.upsert(renamed)
        }
    }

    // 6. Show the result.
    Out.section("6/\(steps) Audit")
    if recovered.isEmpty {
        Out.say("  Nothing to audit: no server was moved.")
    } else {
        try runAudit(aliases: Set(recovered.map(\.alias)), paths: paths, exportBackup: failed.isEmpty)
    }

    if !enrolled.isEmpty {
        let pendingCA = failed.filter { $0.entry.temporaryAccess != nil }.map(\.entry.alias)
        let unconfirmed = recovered.filter { $0.temporaryAccess?.verified == false }.map(\.alias)
        let manual = recovered.filter { $0.temporaryAccess?.caRotation != nil }.map(\.alias)
        if pendingCA.isEmpty && manual.isEmpty {
            Out.say("\nThe lost Mac's CA was removed from authorized_keys on every enrolled server. Trust set up elsewhere (for example TrustedUserCAKeys in sshd_config) is not checked.")
        }
        if !pendingCA.isEmpty {
            Out.say("\nNot recovered yet, so the lost Mac's keys and CA are still trusted there: \(pendingCA.joined(separator: ", ")).")
        }
        if !manual.isEmpty {
            Out.say("\nThe inventory's record of a lost Mac's CA is damaged for: \(manual.joined(separator: ", ")). Remove the cert-authority lines you do not recognize from their ~/.ssh/authorized_keys by hand.")
        }
        if !unconfirmed.isEmpty {
            Out.say("""

            Temporary access is not confirmed yet on: \(unconfirmed.joined(separator: ", ")). The lost Mac's CA is gone
            there, but a certificate through this Mac's CA did not log in. Fix the cause, then run
            `\(tool) authorize NAME --temporary-access` for each of them.
            """)
        }
    }
    if failed.isEmpty {
        Out.say("""

        All servers now trust this Mac. \(rotating
            ? "The old emergency kit was removed from every server: you can destroy it."
            : "Keep the emergency kit you used: it is still the one every server trusts.")
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

/// Refuses to recover with a Touch ID key that the inventory already lists:
/// recovering would remove the key this Mac is using.
func refuseKeysInUse(_ inventory: Inventory, identity: StoredIdentity?, paths: AgentPaths) throws {
    if let identity, inventory.servers.contains(where: { $0.loginKeyFingerprint == identity.fingerprint }) {
        throw UsageError(description: """
        this Mac's Touch ID key (\(identity.fingerprint)) is the one the inventory lists,
        so recovering would remove the key this Mac is using. If it stopped working
        (for example, fingerprints changed), move \(paths.displayPath(paths.directory)) aside and run recover again.
        """)
    }
    // Recovering would also remove the temporary-access CA this Mac uses.
    let recordedCAs = Set(inventory.servers.compactMap { $0.temporaryAccess?.caFingerprint })
    if let ca = try? CertificateAuthorityStore.load(from: paths), recordedCAs.contains(ca.fingerprint) {
        throw UsageError(description: """
        this Mac's temporary-access CA (\(ca.fingerprint)) is the one the inventory lists, so
        recovering would remove it from the servers. recover is for a new Mac.
        """)
    }
    if !paths.isDefault, let main = try? CertificateAuthorityStore.load(from: AgentPaths(directory: AgentPaths.defaultDirectory)),
       recordedCAs.contains(main.fingerprint) {
        throw UsageError(description: """
        this Mac's main temporary-access CA (\(main.fingerprint)) is the one the inventory lists.
        recover is for a new Mac; run `\(tool) recovery test emergency-kit.txt` to rehearse.
        """)
    }
    // With another TOUCHID_SSH_AGENT_DIR, the Mac's main key would not be seen
    // above, and recover would remove it from the servers.
    let mainPaths = AgentPaths(directory: AgentPaths.defaultDirectory)
    if !paths.isDefault, let main = try? IdentityStore.load(from: mainPaths),
       inventory.servers.contains(where: { $0.loginKeyFingerprint == main.fingerprint }) {
        throw UsageError(description: """
        this Mac's main Touch ID key (\(main.fingerprint), in \(mainPaths.displayPath(AgentPaths.defaultDirectory)))
        is the one the inventory lists. recover is for a new Mac: running it here with another
        directory would remove this Mac's key from the servers. To rehearse a recovery on this
        Mac, run `\(tool) recovery test emergency-kit.txt`, which changes nothing.
        """)
    }
}

/// Asks whether to replace the kit's emergency key. Enter means replace.
func askReplaceEmergencyKey(_ key: RecoveryKey) throws -> Bool {
    Out.say("""
      The servers trust this kit's emergency key (\(key.fingerprint)).

        Replace  You save a new kit with a new passphrase, and this kit's key
                 is removed from every server. Choose it if anyone else may
                 have seen this kit or its passphrase, or if you are not sure.
        Keep     Nothing new to save: this kit stays your emergency kit.
    """)
    while let answer = Terminal.ask("Replace the emergency key with a new kit? [Y/n]: ")?
        .trimmingCharacters(in: .whitespaces).lowercased() {
        if ["", "y", "yes"].contains(answer) { return true }
        if ["n", "no"].contains(answer) { return false }
    }
    throw UsageError(description: "no answer, so no server was changed.")
}

/// Moves one server to this Mac. Old credentials are removed only after the
/// new Touch ID login works, and only lines whose key is exactly the lost
/// Mac's key, one of its recorded CAs, or the used emergency key are touched;
/// this Mac's keys and CA never are. On a server enrolled for temporary access
/// (`caPlan`), this Mac's CA is added and checked with a certificate login; if
/// that check fails, the lost Mac's CA is still removed (only that Mac could use
/// it) and the enrollment is recorded as unconfirmed. With `viaTouchID`, an
/// earlier run already installed this Mac's key and the kit no longer logs in.
func recoverServer(_ entry: InventoryEntry, local: InventoryEntry?, configFile: String?, agent: EmergencyAgent,
                   viaTouchID: Bool, oldEmergency: String?, identity: StoredIdentity, newEmergency: RecoveryKey,
                   caPlan: RecoveryCA?, paths: AgentPaths) -> (entry: InventoryEntry, ok: Bool, text: String) {
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
    func session(_ script: String) -> (ok: Bool, output: String, error: String) {
        guard viaTouchID else { return RemoteKeys.emergencySession(target, agent: agent, knownHosts: policy, script: script) }
        let result = RemoteKeys.runWithTouchIDKey(script, on: target, paths: paths, identity: identity, extraArguments: policy.arguments)
        return (result.login == .ok, result.output, result.login == .ok ? "" : describe(result.login))
    }

    let rotation = caPlan?.rotation(for: entry, local: local)
    var newKeys = [AuthorizedKey.login(identity), AuthorizedKey.recovery(newEmergency)]
    if let caPlan, let rotation {
        newKeys.append(AuthorizedKey(label: CATrust.label, type: SSHKeyFormat.keyType, blob: caPlan.ca.publicKeyBlob,
                                     comment: caPlan.ca.comment, options: rotation.authorizedKeyOptions))
    }
    let added = session(RemoteKeys.installScript(newKeys) + RemoteKeys.listing)
    guard added.ok, RemoteKeys.containsListing(added.output) else {
        return fail("the \(viaTouchID ? "Touch ID key" : "emergency key") could not log in: \(added.error)")
    }
    let report = RemoteKeys.parse(added.output)
    Out.say("  Touch ID key \(report["login"] == "added" ? "added" : "already there"), "
        + "emergency key \(report["recovery"] == "added" ? "added" : "already there")"
        + (rotation == nil ? "" : ", this Mac's CA \(report[CATrust.label] == "added" ? "added" : "already there")"))
    if case .pinned = policy, let keys = entry.hostKeys { try? HostKeys.remember(keys, for: resolved) }
    // Why the new CA is not confirmed, if it is not; it never holds back the old keys.
    var caProblem: String?
    if let caPlan, let rotation {
        caPlan.record(.replacementAdded, for: entry)
        let scope = CATrust.inspect(RemoteKeys.listedLines(added.output), caBlob: caPlan.ca.publicKeyBlob, principal: rotation.principal)
        if !scope.isScoped { caProblem = "this Mac's CA line is not scoped as expected (\(scope.summary))" }
    }

    Out.say("  Checking the Touch ID login (approve the Touch ID prompt)...")
    let check = RemoteKeys.verifyLogin(on: target, paths: paths, identity: identity)
    guard check == .ok else { return fail("old keys kept, because the new Touch ID key did not log in: \(describe(check))") }

    if let caPlan, let rotation {
        caPlan.record(.replacementVerified, for: entry)
        if caProblem == nil {
            Out.say("  Checking a certificate login through this Mac's CA (no command runs)...")
            let (credential, error) = caPlan.validationCredential()
            if let credential {
                let hostKeys = entry.hostKeys?.isEmpty == false ? (entry.hostKeys ?? []) : HostKeys.known(for: resolved)
                if case .failed(let reason) = credential.check(hostname: entry.hostname, user: entry.user, port: entry.port,
                                                               principal: rotation.principal, hostKeys: hostKeys) {
                    caProblem = "a certificate through this Mac's CA did not log in: \(reason)"
                }
            } else {
                caProblem = error ?? "no validation certificate"
            }
        }
    }

    // Never remove this Mac's keys or CA, whatever the fingerprints say.
    let protected: Set<Data> = Set([identity.publicKeyBlob, newEmergency.blob] + (caPlan.map { [$0.ca.publicKeyBlob] } ?? []))
    let retired = Set([entry.loginKeyFingerprint] + (oldEmergency.map { [$0] } ?? []))
    let (oldCAs, damagedCAs) = caPlan?.oldCAs(for: entry) ?? ([], [])
    let oldCABlobs = Set(oldCAs.compactMap(\.blob))
    var seen = Set<Data>()
    let doomed = RemoteKeys.listedLines(added.output).compactMap { RemoteKeys.keyBlob(inAuthorizedKeysLine: $0) }
        .filter { (retired.contains(SSHKeyFormat.fingerprint(blob: $0)) || oldCABlobs.contains($0))
            && !protected.contains($0) && seen.insert($0).inserted }
    if !doomed.isEmpty {
        caPlan?.record(.retirementStarted, for: entry)
        let removed = session(RemoteKeys.removeScript(doomed))
        let remainingLines = RemoteKeys.listedLines(removed.output)
        let remaining = remainingLines.compactMap { RemoteKeys.keyBlob(inAuthorizedKeysLine: $0) }
        guard removed.ok, RemoteKeys.containsListing(removed.output), !remaining.contains(where: doomed.contains),
              remaining.contains(identity.publicKeyBlob), remaining.contains(newEmergency.blob) else {
            return fail("the new keys work, but the old keys could not be removed: \(removed.error)")
        }
    }
    // Test-only: simulates a crash after the server changed and before the
    // inventory records it, so the tests can resume a real interrupted run.
    if ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_TEST_INTERRUPT"] == "after-removal:\(entry.alias)" {
        fflush(stdout)
        exit(99)
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
    // A server whose CA work was already done keeps this Mac's record of it.
    updated.temporaryAccess = local?.temporaryAccess ?? entry.temporaryAccess
    var caText = ""
    if let caPlan, let rotation, let base = caPlan.ownEnrollment(local) ?? entry.temporaryAccess {
        var enrollment = base
        let own = caPlan.ownEnrollment(local) != nil
        enrollment.caPublicKey = caPlan.ca.authorizedKeyLine
        enrollment.caFingerprint = caPlan.ca.fingerprint
        enrollment.principal = rotation.principal
        enrollment.authorizedKeyOptions = rotation.authorizedKeyOptions
        if !own { enrollment.enrolledAt = .wholeSecondsNow }
        enrollment.verified = caProblem == nil
        enrollment.lastAudit = .wholeSecondsNow
        // Grants of the lost Mac are history; none is restored.
        if !own { enrollment.lastGrant = nil }
        enrollment.retiredCAFingerprints = Array(Set((enrollment.retiredCAFingerprints ?? []) + oldCAs.map(\.fingerprint))).sorted()
        // A damaged record of an old CA cannot be matched safely: it stays
        // pending, for removal by hand.
        enrollment.caRotation = damagedCAs.isEmpty ? nil : rotation
        let removedCAs = oldCAs.isEmpty ? "" : "the lost Mac's CA was removed"
        if let caProblem {
            enrollment.lastAuditResult = "recovered; \(removedCAs.isEmpty ? "" : removedCAs + "; ")temporary access not confirmed: "
                + "\(caProblem). Run authorize --temporary-access again"
            caText = "; \(removedCAs.isEmpty ? "" : removedCAs + "; ")! temporary access not confirmed (\(caProblem))"
        } else {
            enrollment.lastAuditResult = "recovered: this Mac's CA works\(removedCAs.isEmpty ? "" : "; " + removedCAs)"
            caText = "; the lost Mac's CA replaced by this Mac's"
        }
        if !damagedCAs.isEmpty {
            caText += "; ! remove by hand the CA \(damagedCAs.map(\.fingerprint).joined(separator: ", ")) (damaged record)"
        }
        updated.temporaryAccess = enrollment
    }
    let removedText = doomed.isEmpty ? "no old key was left to remove" : "removed \(doomed.count) old key\(doomed.count == 1 ? "" : "s")"
    return (updated, true, "moved to this Mac; \(removedText)\(caText)")
}

/// Logs in to every server with the emergency key only, in order, and returns
/// which ones accepted it. Nothing changes: unknown host keys go to a scratch file.
func emergencyLogins(_ inventory: Inventory, agent: EmergencyAgent, configFile: String?) -> [Bool] {
    inventory.servers.map { entry in
        let target = SSHTarget(destination: "\(entry.user)@\(entry.hostname)", port: entry.port, configFile: configFile)
        let resolved = try? RemoteKeys.resolve(target)
        let policy: KnownHostsPolicy
        if let resolved, let keys = entry.hostKeys, !keys.isEmpty,
           let pinned = try? KnownHostsPolicy.pinned(keys, for: resolved, in: agent.directory) {
            policy = pinned
        } else {
            policy = .acceptNew(agent.directory.appendingPathComponent("known_hosts-test"))
        }
        // Enrolled servers also print authorized_keys (read only) to report the CA trust.
        let session = RemoteKeys.emergencySession(target, agent: agent, knownHosts: policy,
                                                  script: entry.temporaryAccess == nil ? nil : RemoteKeys.listing)
        Out.say("  \(session.ok ? "✓" : "✗") \(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))"
            + (session.ok ? "" : ": \(session.error)"))
        if session.ok, let enrollment = entry.temporaryAccess {
            if let blob = enrollment.caBlob {
                let report = CATrust.inspect(RemoteKeys.listedLines(session.output), caBlob: blob, principal: enrollment.principal)
                Out.say("      temporary access: \(report.summary) (CA \(enrollment.caFingerprint), principal \(enrollment.principal))")
            } else {
                Out.say("      temporary access: the inventory's CA key does not match its fingerprint")
            }
        }
        return session.ok
    }
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

/// Keeps a dated copy of the backup this kit opens, next to it, before any
/// server changes; a later run reuses an identical copy instead of adding one.
/// Only needed when that backup lives in this Mac's backup folder, where a
/// later command could rewrite it for another key.
@discardableResult
func preserveOldBackup(_ inventoryFile: URL, paths: AgentPaths) -> URL? {
    guard let folder = SettingsStore.load(from: paths).backupDirectory,
          inventoryFile.deletingLastPathComponent().standardizedFileURL == folder.standardizedFileURL,
          let original = FileManager.default.contents(atPath: inventoryFile.path) else { return nil }
    let existing = ((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [])
        .filter { $0.hasPrefix("inventory-before-recovery-") && $0.hasSuffix(".age") }.sorted()
    if let same = existing.first(where: { FileManager.default.contents(atPath: folder.appendingPathComponent($0).path) == original }) {
        return folder.appendingPathComponent(same)
    }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd-HHmmss"
    let copy = folder.appendingPathComponent("inventory-before-recovery-\(formatter.string(from: Date())).age")
    guard (try? FileManager.default.copyItem(at: inventoryFile, to: copy)) != nil else { return nil }
    Out.say("\nThe backup this kit opens was copied to \(paths.displayPath(copy)), in case a later step rewrites it.")
    return copy
}

/// recover checks the Touch ID login on every server, so the agent must run.
func ensureAgentRunning(paths: AgentPaths) throws {
    guard !AgentClient.isListening(socketPath: paths.socket.path) else { return }
    // The LaunchAgent label is shared, so installing it here would repoint this
    // Mac's real agent to another directory.
    guard paths.isDefault else {
        throw UsageError(description: """
        no agent is running for \(paths.displayPath(paths.directory)). Start one in another
        terminal with `TOUCHID_SSH_AGENT_DIR=\(Terminal.shellQuoted(paths.directory.path)) \(tool) agent`.
        """)
    }
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

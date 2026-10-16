import Darwin
import Foundation
import TouchIDSSHCore

// MARK: - Backup folder

/// Suggested backup folder when iCloud Drive is set up on this Mac.
func suggestedBackupFolder() -> String? {
    let iCloud = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Mobile Documents/com~apple~CloudDocs")
    guard FileManager.default.fileExists(atPath: iCloud.path) else { return nil }
    return iCloud.appendingPathComponent("touchid-ssh-agent").path
}

/// Validates and stores the backup folder, creating it if its parent exists,
/// then writes the encrypted inventory there right away.
func setBackupFolder(_ input: String, paths: AgentPaths) throws {
    var settings = SettingsStore.load(from: paths)
    if input.lowercased() == "none" {
        settings.backupPath = nil
        try SettingsStore.save(settings, to: paths)
        Out.say("Backup folder cleared. The inventory now only lives on this Mac and is lost with it.")
        return
    }

    let folder = URL(fileURLWithPath: (input as NSString).expandingTildeInPath).standardizedFileURL
    var isDirectory: ObjCBool = false
    if FileManager.default.fileExists(atPath: folder.path, isDirectory: &isDirectory) {
        guard isDirectory.boolValue else { throw UsageError(description: "\(folder.path) is not a folder") }
    } else {
        let parent = folder.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: parent.path) else {
            throw UsageError(description: "\(parent.path) does not exist")
        }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
    }
    guard FileManager.default.isWritableFile(atPath: folder.path) else {
        throw UsageError(description: "\(folder.path) is not writable")
    }

    let previous = settings.backupPath
    settings.backupPath = folder.path
    try SettingsStore.save(settings, to: paths)
    Out.say("Backup folder: \(paths.displayPath(folder))")
    reportBackup(InventoryBackup.export(paths: paths, settings: settings), paths: paths)
    if previous != nil, previous != folder.path {
        Out.say("Your emergency kit names the previous folder. Note the new one next to the kit.")
    }
}

func reportBackup(_ outcome: InventoryBackup.Outcome, paths: AgentPaths) {
    switch outcome {
    case .written(let file):
        Out.say("Encrypted inventory saved to \(paths.displayPath(file)).")
    case .keptExisting(let file):
        Out.say("""
        Kept the existing \(paths.displayPath(file)): this Mac's inventory is empty,
        so it was not overwritten. If you are recovering from a lost Mac, run
        `\(tool) recover emergency-kit.txt`.
        """)
    case .noBackupFolder:
        Out.say("Warning: no backup folder, so the inventory only lives on this Mac. Set one with `\(tool) set backup-path DIR`.")
    case .noRecoveryKey:
        Out.say("The encrypted inventory will be written once an emergency key exists (`\(tool) setup`).")
    case .ageMissing:
        Out.say("Warning: age is not installed, so the encrypted inventory was NOT updated. Install it with `brew install age`.")
    case .failed(let reason):
        Out.say("Warning: the encrypted inventory was NOT updated: \(reason)")
    }
}

// MARK: - Emergency kit

/// With `duringRecovery`, recover itself installs the new key on the servers
/// and writes the backup once every server moved, so neither happens here.
func createEmergencyKit(paths: AgentPaths, replace: Bool, ownPassphrase: Bool, showHeader: Bool = false,
                        duringRecovery: Bool = false) throws {
    try Terminal.requireInteractive("recovery create")
    if showHeader { Out.header("recovery create", "a new emergency kit") }
    let previous = try RecoveryStore.load(from: paths)
    if let previous, !replace {
        throw RecoveryError.alreadyConfigured(previous.fingerprint)
    }
    let identity = try IdentityStore.load(from: paths)
    let settings = SettingsStore.load(from: paths)

    Out.say("""
    The emergency kit gets you back into your servers if this Mac is lost,
    stolen or broken. It holds an emergency SSH key, protected by a passphrase,
    that is installed on every server next to your Touch ID key.
    """)

    guard let passphrase = ownPassphrase ? askOwnPassphrase() : showGeneratedPassphrase() else {
        Out.say("Nothing was created.")
        return
    }

    let details = EmergencyKitBuilder.Details(
        macName: IdentityStore.macName(),
        loginKeyFingerprint: identity?.fingerprint,
        backupFolder: settings.backupDirectory.map { paths.displayPath($0) }
    )
    Out.say("Generating the emergency key...")
    let kit = try EmergencyKitBuilder.build(passphrase: passphrase, details: details, paths: paths)

    // Scripted runs (the test suite) set TOUCHID_SSH_AGENT_NO_REVEAL to skip Finder.
    if ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_NO_REVEAL"] == nil {
        _ = try? Command.run("/usr/bin/open", ["-R", kit.file.path])
    }
    Out.say("""

    Your emergency kit is ready (a Finder window shows it):

        \(kit.file.path)

    The key inside is encrypted with your passphrase. Store the file outside
    this Mac (password manager, USB drive, or an email to yourself) and keep
    the passphrase somewhere else. If the Mac is stolen, the kit must not go
    with it.
    """)
    guard Terminal.confirm(word: "SAVED", cancelWord: "ABORT",
                           prompt: "Type SAVED once the kit is stored outside this Mac (or ABORT): ") else {
        EmergencyKitBuilder.discard(paths: paths)
        Out.say("Aborted. The kit was erased and nothing was configured.")
        return
    }
    if !FileManager.default.fileExists(atPath: kit.file.path) {
        Out.say("The kit was moved out of its folder. Make sure no copy stays on this Mac (check Desktop and Downloads).")
    }
    let key = try EmergencyKitBuilder.finalize(kit, paths: paths, replace: replace)
    Out.say("\nEmergency key configured: \(key.fingerprint)")
    Out.say("The copy of the kit on this Mac was erased.")
    guard !duringRecovery else { return }
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    if let previous, previous != key {
        Out.say("""
        Your servers still trust the previous emergency key (\(previous.fingerprint)).
        Run `\(tool) authorize` again for each server, then remove the old key's line
        from their ~/.ssh/authorized_keys.
        """)
    }
}

/// Shows a generated passphrase once and asks the user to retype it exactly.
func showGeneratedPassphrase() -> String? {
    let passphrase = Passphrase.generate()
    Out.say("\nYour emergency passphrase (shown only this once):")
    Out.boxed(passphrase)
    Out.say("""
    Save it now in your password manager, or write it down. It is all
    lowercase and the dashes are part of it.
    """)
    for attempt in 1...3 {
        guard let typed = Terminal.askHidden("Retype the passphrase to confirm you saved it: ") else { return nil }
        if typed.trimmingCharacters(in: .whitespaces) == passphrase {
            Terminal.clearScreen()
            Out.say("\n✓ Passphrase confirmed.")
            return passphrase
        }
        Out.say(attempt < 3 ? "That does not match. Type it exactly, with the dashes." : "That does not match.")
    }
    Terminal.clearScreen()
    return nil
}

func askOwnPassphrase() -> String? {
    Out.say("Choose a passphrase of at least \(Passphrase.minimumCustomLength) characters, different from your Mac password.")
    for _ in 1...3 {
        guard let first = Terminal.askHidden("Passphrase: "), let second = Terminal.askHidden("Repeat it: ") else { return nil }
        if first != second {
            Out.say("The passphrases do not match.")
        } else if first.count < Passphrase.minimumCustomLength {
            Out.say("Too short: use at least \(Passphrase.minimumCustomLength) characters.")
        } else {
            return first
        }
    }
    return nil
}

func importEmergencyKey(_ file: String, paths: AgentPaths, replace: Bool) throws {
    let previous = try RecoveryStore.load(from: paths)
    let url = URL(fileURLWithPath: (file as NSString).expandingTildeInPath)
    let key = try RecoveryStore.importPublicKey(from: url, into: paths, replace: replace)
    Out.say("Emergency key imported: \(key.fingerprint) (\(key.type))")
    Out.say("Only the public key was copied; keep the private key where it is, outside this Mac.")
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    if let previous, previous != key {
        Out.say("Run `\(tool) authorize` again for each server to install the new emergency key, then remove the old one (\(previous.fingerprint)).")
    }
}

func recovery(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let (positional, options) = try parseOptions(arguments.dropFirst(), booleans: ["replace", "own-passphrase"])
    switch arguments.first {
    case "create":
        try createEmergencyKit(paths: paths, replace: options["replace"] != nil,
                               ownPassphrase: options["own-passphrase"] != nil, showHeader: true)
    case "import":
        guard positional.count == 1 else { throw UsageError(description: "usage: \(tool) recovery import FILE.pub [--replace]") }
        try importEmergencyKey(positional[0], paths: paths, replace: options["replace"] != nil)
    case "test":
        try recover(arguments.dropFirst(), paths: paths, dryRun: true)
    case "pubkey":
        guard let key = try RecoveryStore.load(from: paths) else {
            throw UsageError(description: "no emergency key yet. Run `\(tool) setup`.")
        }
        print(key.line)
    default:
        throw UsageError(description: "usage: \(tool) recovery create|import|test|pubkey")
    }
}

// MARK: - setup

func setup(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    try Terminal.requireInteractive("setup")
    let (_, options) = try parseOptions(arguments)
    Out.header("setup", "Touch ID key, backup folder and emergency kit")

    Out.section("Step 1 of 3: Touch ID key")
    if let identity = try IdentityStore.load(from: paths) {
        Out.say("Already created: \(identity.fingerprint) (\(identity.comment))")
    } else {
        let policyName = options["biometry"] ?? BiometryPolicy.currentSet.rawValue
        guard let policy = BiometryPolicy(rawValue: policyName) else {
            throw UsageError(description: "--biometry must be current-set or any")
        }
        let identity = try IdentityStore.create(in: paths, policy: policy,
                                                comment: options["comment"] ?? IdentityStore.defaultComment())
        Out.say("Created in the Secure Enclave (policy: \(policy.rawValue)): \(identity.fingerprint)")
    }

    Out.section("Step 2 of 3: backup folder")
    if let folder = SettingsStore.load(from: paths).backupDirectory {
        Out.say("Already set: \(paths.displayPath(folder)). Change it with `\(tool) set backup-path DIR`.")
    } else {
        try askBackupFolder(paths: paths)
    }
    if Command.find("age") == nil {
        Out.say("Warning: age is not installed. Install it with `brew install age` so the inventory backup can be written.")
    }

    Out.section("Step 3 of 3: emergency kit")
    if let key = try RecoveryStore.load(from: paths) {
        Out.say("Already configured: \(key.fingerprint). Replace it with `\(tool) recovery create --replace`.")
    } else {
        let choice = Terminal.ask("Create a new emergency key (recommended) or import an existing public key? [new/import]: ")?
            .trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        if choice == "import" {
            guard let file = Terminal.ask("Path to the public key (.pub): "), !file.isEmpty else {
                throw UsageError(description: "no file given")
            }
            try importEmergencyKey(file, paths: paths, replace: false)
        } else {
            try createEmergencyKit(paths: paths, replace: false, ownPassphrase: false)
        }
    }

    Out.section("Next steps")
    Out.say("""
    1. Install the agent if you have not yet:   \(tool) install
    2. Authorize each server (adds both keys and updates the inventory):
           \(tool) authorize user@server -p PORT
    3. Check everything at any time:            \(tool) status
    """)
}

func askBackupFolder(paths: AgentPaths) throws {
    Out.say("""
    \(tool) keeps a list of the servers you authorize (the inventory). A copy,
    encrypted to your emergency key, is saved in a folder of your choice.
    Choose a folder synced to the cloud (iCloud Drive, Dropbox, Google Drive):
    if this Mac is stolen, that copy is how you find your servers again.
    """)
    let suggestion = suggestedBackupFolder()
    let defaultHint = suggestion.map { " [\(paths.displayPath(URL(fileURLWithPath: $0)))]" } ?? ""
    while true {
        guard let raw = Terminal.ask("Backup folder\(defaultHint), or 'skip': ") else {
            throw UsageError(description: "setup cancelled (end of input)")
        }
        let answer = raw.trimmingCharacters(in: .whitespaces)
        if answer.lowercased() == "skip" {
            Out.say("Without a backup folder the inventory only lives on this Mac and is lost with it.")
            if Terminal.confirm(word: "SKIP", cancelWord: "BACK", prompt: "Type SKIP to continue without one (or BACK to choose a folder): ") {
                Out.say("Skipped. Set it later with `\(tool) set backup-path DIR`.")
                return
            }
            continue
        }
        guard let folder = answer.isEmpty ? suggestion : answer else {
            Out.say("Type a folder path, or 'skip'.")
            continue
        }
        do {
            try setBackupFolder(folder, paths: paths)
            return
        } catch {
            Out.say("\(error)")
        }
    }
}

// MARK: - authorize and audit

func requireRecoveryKey(_ paths: AgentPaths) throws -> RecoveryKey {
    guard let key = try RecoveryStore.load(from: paths) else {
        throw UsageError(description: "no emergency key yet. Run `\(tool) setup` (or `\(tool) recovery create`) first, so every server gets both keys.")
    }
    return key
}

func authorize(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let usageText = "usage: \(tool) authorize [user@]host [-p PORT] [-F SSH_CONFIG] [--alias NAME] [--temporary-access] [-- EXTRA_SSH_ARGS]"
    var destination: String?
    var port: Int?
    var configFile: String?
    var alias: String?
    var temporaryAccess = false
    var extra: [String] = []
    var iterator = arguments.makeIterator()
    while let argument = iterator.next() {
        switch argument {
        case "-p":
            guard let value = iterator.next(), let number = Int(value) else { throw UsageError(description: usageText) }
            port = number
        case "-F":
            guard let value = iterator.next() else { throw UsageError(description: usageText) }
            configFile = (value as NSString).expandingTildeInPath
        case "--alias":
            guard let value = iterator.next() else { throw UsageError(description: usageText) }
            alias = value
        case "--temporary-access":
            temporaryAccess = true
        case "--":
            while let rest = iterator.next() { extra.append(rest) }
        default:
            guard destination == nil, !argument.hasPrefix("-") else { throw UsageError(description: usageText) }
            destination = argument
        }
    }
    guard let destination else { throw UsageError(description: usageText) }

    let identity = requireIdentity(paths)
    let recoveryKey = try requireRecoveryKey(paths)
    guard AgentClient.isListening(socketPath: paths.socket.path) else {
        throw UsageError(description: "the agent is not running, so the Touch ID key cannot be checked. Run `\(tool) install` first.")
    }

    let target = SSHTarget(destination: destination, port: port, configFile: configFile, bootstrapArguments: extra)
    let resolved = try RemoteKeys.resolve(target)
    let existing = try InventoryStore.load(from: paths).servers.first {
        $0.hostname == resolved.hostname && $0.port == resolved.port && $0.user == resolved.user
    }
    let plan = temporaryAccess ? try EnrollmentPlan.prepare(paths: paths, resolved: resolved, existing: existing) : nil
    let steps = plan == nil ? 4 : 5
    Out.header("authorize", plan == nil ? "install both keys on \(destination)" : "install both keys and the CA on \(destination)")
    var keys = [AuthorizedKey.login(identity), AuthorizedKey.recovery(recoveryKey)]
    Out.say("""
    Authorizing \(resolved.user)@\(resolved.hostname):\(resolved.port)
      Touch ID key   \(identity.fingerprint)
      emergency key  \(recoveryKey.fingerprint)
    """)
    if let plan {
        keys.append(plan.key)
        Out.say("  CA             \(plan.ca.fingerprint)\(plan.created ? " (new)" : ""), for principal \(plan.principal)")
        try plan.recordIntent(paths: paths)
    }

    Out.section("1/\(steps) Adding the keys (with your current access to the server)")
    let report: [String: Bool]
    var listing: [String] = []
    do {
        // Without --temporary-access, exactly the 0.1.0 script; the listing is
        // only needed to check a CA line's scope.
        if plan == nil {
            report = try RemoteKeys.install(keys, on: target)
        } else {
            (report, listing) = try RemoteKeys.installAndList(keys, on: target)
        }
    } catch {
        let portFlag = port.map { " -p \($0)" } ?? ""
        throw UsageError(description: """
        could not reach or log in to \(resolved.user)@\(resolved.hostname):\(resolved.port).
        Check the address and the port, and that your current access works:
            ssh\(portFlag) \(destination)
        If the server has a Host alias in ~/.ssh/config, authorize the alias instead,
        so its port and keys apply. (\(error))
        """)
    }
    let names = ["login": "Touch ID key ", "recovery": "emergency key", CATrust.label: "CA trust     "]
    for key in keys {
        Out.say("  \(names[key.label] ?? key.label): \(report[key.label] == true ? "added" : "already there")")
    }

    Out.section("2/\(steps) Checking the Touch ID key (approve the Touch ID prompt)")
    let check = RemoteKeys.verifyLogin(on: SSHTarget(destination: destination, port: port, configFile: configFile),
                                       paths: paths, identity: identity)
    Out.say("  \(describe(check))")

    var enrollment: TemporaryAccessEnrollment?
    var enrolled = true
    if let plan {
        Out.section("3/\(steps) Checking a certificate login through the CA (approve the Touch ID prompt)")
        let outcome = plan.verify(listing: listing, resolved: resolved, target: target, paths: paths)
        enrollment = outcome.enrollment
        enrolled = outcome.ok
        for line in outcome.lines { Out.say("  " + line) }
    }

    Out.section("\(steps - 1)/\(steps) ssh config")
    let friendlyName = try offerSSHConfig(destination: destination, suggestedName: alias, resolved: resolved,
                                          configFile: configFile, paths: paths)

    Out.section("\(steps)/\(steps) Updating the inventory")
    let entryAlias = friendlyName ?? alias ?? destination
    let count = try InventoryStore.update(paths) { inventory -> Int in
        inventory.mac = IdentityStore.defaultComment()
        // Durable CA trust survives re-authorizing without --temporary-access.
        let previous = inventory.servers.first {
            $0.hostname == resolved.hostname && $0.port == resolved.port && $0.user == resolved.user
        }?.temporaryAccess
        // One entry per server: drop older entries for the same user, host and port.
        inventory.servers.removeAll {
            $0.hostname == resolved.hostname && $0.port == resolved.port && $0.user == resolved.user && $0.alias != entryAlias
        }
        inventory.upsert(InventoryEntry(
            alias: entryAlias, destination: friendlyName ?? destination,
            hostname: resolved.hostname, user: resolved.user, port: resolved.port, sshConfigFile: configFile,
            loginKeyFingerprint: identity.fingerprint, recoveryKeyFingerprint: recoveryKey.fingerprint,
            authorizedAt: .wholeSecondsNow, hostKeys: HostKeys.known(for: resolved),
            temporaryAccess: enrollment ?? previous
        ))
        return inventory.servers.count
    }
    Out.say("  \(entryAlias) saved (\(count) server\(count == 1 ? "" : "s") in the inventory)\(enrollment?.verified == true ? ", with temporary access" : "").")
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    if plan != nil, enrolled {
        Out.say("""

        Request temporary access with: \(tool) access \(entryAlias) --for 2h
        To let an AI agent request it, add the instructions to its file once, for example:
            \(tool) instructions --add-to ~/.claude/CLAUDE.md
        """)
    }

    guard check == .ok, enrolled else { exit(1) }
}

/// Step 3 of authorize: make `ssh NAME` use the Touch ID agent. Returns a new
/// friendly name when one was added, so the inventory records it.
func offerSSHConfig(destination: String, suggestedName: String?, resolved: ResolvedTarget,
                    configFile: String?, paths: AgentPaths) throws -> String? {
    let file = SSHConfigFile.forTarget(configFile: configFile)
    let shown = paths.displayPath(file.url)
    let hostPart = destination.split(separator: "@").last.map(String.init) ?? destination
    let aliases = file.hostAliases()
    if resolved.usesTouchIDAgent(paths) {
        Out.say("  ✓ `ssh \(destination)` already uses the Touch ID agent.")
        return nil
    }
    // An existing Host may already reach this server through the agent.
    for name in aliases where name != hostPart {
        if let other = try? RemoteKeys.resolve(SSHTarget(destination: name, configFile: configFile)),
           other.hostname == resolved.hostname, other.port == resolved.port, other.user == resolved.user,
           other.usesTouchIDAgent(paths) {
            Out.say("  ✓ `ssh \(name)` already reaches this server through the Touch ID agent.")
            return name
        }
    }
    let block = { (name: String) in
        SSHConfigFile.block(alias: name, hostname: resolved.hostname, user: resolved.user,
                            port: resolved.port == 22 ? nil : resolved.port, paths: paths)
    }
    let indented = { (text: String) in text.split(separator: "\n").map { "    " + $0 }.joined(separator: "\n") }
    guard Terminal.isInteractive else {
        Out.say("  To log in with `ssh NAME` through the Touch ID agent, add this to \(shown):\n")
        Out.say(indented(block(suggestedName ?? "NAME")))
        return nil
    }

    if aliases.contains(hostPart), !destination.contains("@") {
        Out.say("  Host \(hostPart) in \(shown) does not use the Touch ID agent yet.")
        Out.say("  These lines would be added to it:\n")
        Out.say(indented(SSHConfigFile.agentLines(paths: paths).joined(separator: "\n")))
        guard Terminal.ask("Add them? [y/N]: ")?.lowercased().hasPrefix("y") == true else {
            Out.say("  Left unchanged.")
            return nil
        }
        let backup = try file.insertAgentLines(intoHost: hostPart, paths: paths)
        Out.say("  ✓ Updated Host \(hostPart) (previous version saved as \(paths.displayPath(backup))).")
        return nil
    }

    Out.say("  Give this server a short name, to log in with `ssh NAME`.")
    while true {
        let hint = suggestedName.map { " [\($0)]" } ?? ""
        guard let answer = Terminal.ask("Name\(hint), or Enter to skip: ") else { return nil }
        let typed = answer.trimmingCharacters(in: .whitespaces)
        let name = typed.isEmpty ? (suggestedName ?? "") : typed
        if name.isEmpty {
            Out.say("  Skipped.")
            return nil
        }
        guard name.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else {
            Out.say("  Use letters, digits, dots, dashes or underscores.")
            continue
        }
        guard !aliases.contains(name) else {
            Out.say("  \(name) is already a Host in \(shown). Choose another name.")
            continue
        }
        Out.say("\n" + indented(block(name)))
        guard Terminal.ask("Add it to \(shown)? [Y/n]: ").map({ !$0.lowercased().hasPrefix("n") }) == true else {
            Out.say("  Not added.")
            return nil
        }
        try file.append(block: block(name))
        Out.say("  ✓ Added. From now on: ssh \(name)")
        return name
    }
}

/// How `ssh` reaches an inventory server: the first Host alias (or the
/// entry's own name) that resolves to it and uses the Touch ID agent.
func sshConfigStatus(for entry: InventoryEntry, paths: AgentPaths) -> (ok: Bool, text: String) {
    let file = SSHConfigFile.forTarget(configFile: entry.sshConfigFile)
    for name in [entry.alias] + file.hostAliases() {
        guard let resolved = try? RemoteKeys.resolve(SSHTarget(destination: name, configFile: entry.sshConfigFile)),
              resolved.hostname == entry.hostname, resolved.port == entry.port else { continue }
        if resolved.usesTouchIDAgent(paths) {
            return (true, "ssh config: `ssh \(name)` uses the Touch ID agent")
        }
    }
    return (false, "ssh config: no Host uses the Touch ID agent for this server. Add one with "
        + "`\(tool) config NAME --host \(entry.hostname) --user \(entry.user) --port \(entry.port)`")
}

func describe(_ check: LoginCheck) -> String {
    switch check {
    case .ok: return "✓ The server accepted the Touch ID key."
    case .agentNotRunning: return "✗ The agent is not running (`\(tool) install`)."
    case .otherKeyUsed: return "! Logged in, but with another key from your ssh configuration, not the Touch ID key."
    case .failed(let reason): return "✗ Login with the Touch ID key failed: \(reason)"
    }
}

func audit(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let inventory = try InventoryStore.load(from: paths)
    guard !inventory.servers.isEmpty else {
        Out.say("The inventory is empty. Add servers with `\(tool) authorize`.")
        return
    }
    Out.header("audit", "check the keys on every server")
    if try runAudit(aliases: Set(arguments), paths: paths) > 0 { exit(1) }
}

/// Checks the inventory servers named in `aliases` (all when empty), records
/// the results and returns how many need attention. `exportBackup` is false
/// when the backup must stay as it is (a partial recovery: the old kit has to
/// open it again).
@discardableResult
func runAudit(aliases wanted: Set<String>, paths: AgentPaths, exportBackup: Bool = true) throws -> Int {
    let inventory = try InventoryStore.load(from: paths)
    let entries = inventory.servers.filter { wanted.isEmpty || wanted.contains($0.alias) }
    guard !entries.isEmpty else {
        Out.say("No server named \(wanted.sorted().joined(separator: ", ")) in the inventory.")
        return 0
    }
    let identity = requireIdentity(paths)
    let recoveryKey = try requireRecoveryKey(paths)
    let keys = [AuthorizedKey.login(identity), AuthorizedKey.recovery(recoveryKey)]
    let ca = try? CertificateAuthorityStore.load(from: paths)

    Out.say("Checking \(entries.count) server\(entries.count == 1 ? "" : "s"); each one asks for Touch ID.")
    var problems = 0
    var results: [(alias: String, text: String, hostKeys: [String]?, temporary: String?)] = []
    for entry in entries {
        Out.say("\n\(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
        let target = SSHTarget(destination: entry.destination, port: entry.port, configFile: entry.sshConfigFile)
        let outcome = RemoteKeys.audit(target, keys: keys, paths: paths, identity: identity, listing: entry.temporaryAccess != nil)
        let result = auditSummary(outcome)
        Out.say("  \(result.ok ? "✓" : "✗") \(result.text)")
        var serverOK = result.ok
        var temporary: String?
        if let enrollment = entry.temporaryAccess {
            let check = auditTemporaryAccess(enrollment, listing: outcome.listing, currentCA: ca)
            Out.say("  \(check.ok ? "✓" : "✗") temporary access: \(check.text)")
            temporary = check.text
            serverOK = serverOK && check.ok
        }
        if !serverOK { problems += 1 }
        let config = sshConfigStatus(for: entry, paths: paths)
        Out.say("  \(config.ok ? "✓" : "!") \(config.text)")
        // Backfill host keys for entries recorded before they were stored.
        var hostKeys: [String]?
        if outcome.login == .ok, let resolved = try? RemoteKeys.resolve(target) {
            let known = HostKeys.known(for: resolved)
            if !known.isEmpty { hostKeys = known }
        }
        results.append((entry.alias, result.text, hostKeys, temporary))
    }
    // Merged into the current inventory, which may have changed meanwhile.
    try InventoryStore.update(paths) { inventory in
        for result in results {
            guard let index = inventory.servers.firstIndex(where: { $0.alias == result.alias }) else { continue }
            inventory.servers[index].lastAudit = .wholeSecondsNow
            inventory.servers[index].lastAuditResult = result.text
            if let hostKeys = result.hostKeys { inventory.servers[index].hostKeys = hostKeys }
            if let temporary = result.temporary, inventory.servers[index].temporaryAccess != nil {
                inventory.servers[index].temporaryAccess?.lastAudit = .wholeSecondsNow
                inventory.servers[index].temporaryAccess?.lastAuditResult = temporary
            }
        }
    }
    if exportBackup { reportBackup(InventoryBackup.export(paths: paths), paths: paths) }
    Out.say(problems == 0 ? "\nAll servers have both keys." : "\n\(problems) server\(problems == 1 ? "" : "s") need attention: run `\(tool) authorize` for them.")
    return problems
}

/// Checks one server's CA trust from its authorized_keys: the recorded CA is
/// there, scoped to the recorded principal with no broader line, and no
/// retired CA is still trusted.
func auditTemporaryAccess(_ enrollment: TemporaryAccessEnrollment, listing: [String]?,
                          currentCA: StoredIdentity?) -> (ok: Bool, text: String) {
    guard let listing else { return (false, "not checked (the login failed)") }
    guard let caBlob = enrollment.caBlob else {
        return (false, "the recorded CA key does not match its fingerprint; run `\(tool) authorize HOST --temporary-access`")
    }
    let retired = Set((enrollment.retiredCAFingerprints ?? []) + (enrollment.caRotation?.oldCAs.map(\.fingerprint) ?? []))
        .subtracting([enrollment.caFingerprint])
    let report = CATrust.inspect(listing, caBlob: caBlob, principal: enrollment.principal, retiredFingerprints: retired)
    var text = report.summary + " (principal \(enrollment.principal))"
    var ok = report.isScoped && report.retiredLines == 0
    if let rotation = enrollment.caRotation {
        text += "; CA replacement pending (\(rotation.step.rawValue))"
        ok = false
    }
    if let currentCA, currentCA.fingerprint != enrollment.caFingerprint {
        text += "; enrolled with another CA (\(enrollment.caFingerprint))"
        ok = false
    }
    if !enrollment.verified {
        text += "; the certificate login was never confirmed"
        ok = false
    }
    return (ok, text)
}

func auditSummary(_ outcome: AuditOutcome) -> (ok: Bool, text: String) {
    switch outcome.login {
    case .ok, .otherKeyUsed:
        var missing: [String] = []
        if outcome.present["login"] != true { missing.append("Touch ID key") }
        if outcome.present["recovery"] != true { missing.append("emergency key") }
        if !missing.isEmpty { return (false, "missing: \(missing.joined(separator: ", "))") }
        if outcome.login == .otherKeyUsed { return (false, "keys present, but the Touch ID key was not the one accepted") }
        return (true, "both keys present, Touch ID login works")
    case .agentNotRunning:
        return (false, "agent not running")
    case .failed(let reason):
        return (false, "Touch ID login failed: \(reason)")
    }
}

func listInventory(paths: AgentPaths) throws {
    let inventory = try InventoryStore.load(from: paths)
    guard !inventory.servers.isEmpty else {
        Out.say("The inventory is empty. Add servers with `\(tool) authorize`.")
        return
    }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm"
    for entry in inventory.servers {
        let audited = entry.lastAudit.map { "audited \(formatter.string(from: $0)): \(entry.lastAuditResult ?? "")" } ?? "never audited"
        Out.say("\(entry.alias)\t\(entry.user)@\(entry.hostname):\(entry.port)\tauthorized \(formatter.string(from: entry.authorizedAt))\t\(audited)")
        if let enrollment = entry.temporaryAccess {
            Out.say("  temporary access: \(enrollment.verified ? "enrolled" : "NOT confirmed"), CA \(enrollment.caFingerprint), "
                + "principal \(enrollment.principal)"
                + (enrollment.lastAudit.map { ", audited \(formatter.string(from: $0)): \(enrollment.lastAuditResult ?? "")" } ?? ""))
            if let rotation = enrollment.caRotation {
                Out.say("  CA replacement pending (\(rotation.step.rawValue)): \(rotation.oldCAFingerprint) → \(rotation.newCAFingerprint)")
            }
            if let grant = enrollment.lastGrant {
                let end = grant.endedAt.map { "ended \(formatter.string(from: $0)) (\(grant.endReason ?? "ended"))" }
                    ?? "until \(formatter.string(from: grant.expiresAt)), if still running"
                Out.say("  latest grant: \(grant.grantId), serial \(grant.serial), \(end). `\(tool) access status` shows live grants.")
            }
        }
    }
}

// MARK: - status additions

func recoveryStatus(paths: AgentPaths) {
    do {
        if let key = try RecoveryStore.load(from: paths) {
            Out.say("Emergency key:  \(key.fingerprint) (\(key.type))")
        } else {
            Out.say("Emergency key:  none — run `\(tool) setup`")
        }
    } catch {
        Out.say("Emergency key:  error — \(error)")
    }

    let settings = SettingsStore.load(from: paths)
    if let folder = settings.backupDirectory {
        let backup = folder.appendingPathComponent(InventoryBackup.fileName)
        if !FileManager.default.fileExists(atPath: folder.path) {
            Out.say("Backup folder:  \(paths.displayPath(folder)) — MISSING")
        } else if let modified = (try? FileManager.default.attributesOfItem(atPath: backup.path))?[.modificationDate] as? Date {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm"
            Out.say("Backup folder:  \(paths.displayPath(folder)) (inventory.age updated \(formatter.string(from: modified)))")
        } else {
            Out.say("Backup folder:  \(paths.displayPath(folder)) (no inventory.age yet)")
        }
    } else {
        Out.say("Backup folder:  not set — `\(tool) set backup-path DIR`")
    }
    if Command.find("age") == nil {
        Out.say("age:            not installed — `brew install age` (needed for the inventory backup)")
    }

    let inventory = (try? InventoryStore.load(from: paths)) ?? Inventory()
    let count = inventory.servers.count
    Out.say("Inventory:      \(count) server\(count == 1 ? "" : "s")")
    temporaryAccessStatus(paths: paths, inventory: inventory)

    let fileVault = (try? Command.run("/usr/bin/fdesetup", ["status"]))?.stdoutText ?? ""
    if fileVault.contains("FileVault is On") {
        Out.say("FileVault:      on")
    } else {
        Out.say("FileVault:      OFF — turn it on (System Settings > Privacy & Security) to protect the local inventory")
    }
}

/// CA, enrollments, pending replacements and the live grant, for `status`.
func temporaryAccessStatus(paths: AgentPaths, inventory: Inventory) {
    let enrolled = inventory.servers.filter { $0.temporaryAccess != nil }
    do {
        if let ca = try CertificateAuthorityStore.load(from: paths) {
            let current = enrolled.filter { $0.temporaryAccess?.caFingerprint == ca.fingerprint }.count
            Out.say("Temporary CA:   \(ca.fingerprint) (\(current) server\(current == 1 ? "" : "s") enrolled)")
            let other = enrolled.count - current
            if other > 0 {
                Out.say("                ! \(other) server\(other == 1 ? " trusts" : "s trust") another CA; run `\(tool) authorize HOST --temporary-access` for them")
            }
        } else {
            Out.say("Temporary CA:   none — `\(tool) authorize HOST --temporary-access` creates it")
        }
    } catch {
        Out.say("Temporary CA:   error — \(error)")
    }
    let pending = enrolled.filter { $0.temporaryAccess?.caRotation != nil }
    if !pending.isEmpty {
        Out.say("CA replacement: pending on \(pending.map(\.alias).joined(separator: ", ")); run `\(tool) recover` again to finish it")
    }
    let inspections = GrantStore.inspectAll(paths: paths)
    if let active = inspections.lazy.compactMap({ activeGrantDocument($0, paths: paths) }).first {
        Out.say("Temporary access: grant \(active["grant_id"] as? String ?? "") active until \(active["expires_at_local"] as? String ?? "")")
    } else if !enrolled.isEmpty || !inspections.isEmpty {
        Out.say("Temporary access: no active grant")
    }
    let stale = staleList(inspections, excluding: nil, paths: paths)
    if !stale.isEmpty {
        Out.say("                \(stale.count) leftover grant director\(stale.count == 1 ? "y" : "ies") — `\(tool) access cleanup`")
    }
}

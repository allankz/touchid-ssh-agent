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
        print("Backup folder cleared. The inventory now only lives on this Mac and is lost with it.")
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
    print("Backup folder: \(paths.displayPath(folder))")
    reportBackup(InventoryBackup.export(paths: paths, settings: settings), paths: paths)
    if previous != nil, previous != folder.path {
        print("Your emergency kit names the previous folder. Note the new one next to the kit.")
    }
}

func reportBackup(_ outcome: InventoryBackup.Outcome, paths: AgentPaths) {
    switch outcome {
    case .written(let file):
        print("Encrypted inventory saved to \(paths.displayPath(file)).")
    case .noBackupFolder:
        print("Warning: no backup folder, so the inventory only lives on this Mac. Set one with `\(tool) set backup-path DIR`.")
    case .noRecoveryKey:
        print("The encrypted inventory will be written once an emergency key exists (`\(tool) setup`).")
    case .ageMissing:
        print("Warning: age is not installed, so the encrypted inventory was NOT updated. Install it with `brew install age`.")
    case .failed(let reason):
        print("Warning: the encrypted inventory was NOT updated: \(reason)")
    }
}

// MARK: - Emergency kit

func createEmergencyKit(paths: AgentPaths, replace: Bool, ownPassphrase: Bool) throws {
    try Terminal.requireInteractive("recovery create")
    let previous = try RecoveryStore.load(from: paths)
    if let previous, !replace {
        throw RecoveryError.alreadyConfigured(previous.fingerprint)
    }
    let identity = try IdentityStore.load(from: paths)
    let settings = SettingsStore.load(from: paths)

    print("""
    The emergency kit gets you back into your servers if this Mac is lost,
    stolen or broken. It holds an emergency SSH key, protected by a passphrase,
    that is installed on every server next to your Touch ID key.
    """)

    guard let passphrase = ownPassphrase ? askOwnPassphrase() : showGeneratedPassphrase() else {
        print("Nothing was created.")
        return
    }

    let details = EmergencyKitBuilder.Details(
        macName: IdentityStore.macName(),
        loginKeyFingerprint: identity?.fingerprint,
        backupFolder: settings.backupDirectory.map { paths.displayPath($0) }
    )
    print("Generating the emergency key...")
    let kit = try EmergencyKitBuilder.build(passphrase: passphrase, details: details, paths: paths)

    // Scripted runs (the test suite) set TOUCHID_SSH_AGENT_NO_REVEAL to skip Finder.
    if ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_NO_REVEAL"] == nil {
        _ = try? Command.run("/usr/bin/open", ["-R", kit.file.path])
    }
    print("""

    Your emergency kit is ready (a Finder window shows it):

        \(kit.file.path)

    Save this file in your password manager (as an attachment) or on an
    encrypted drive. Do not keep a copy on this Mac: if the Mac is stolen,
    the kit must not go with it.

    """)
    guard Terminal.confirm(word: "SAVED", cancelWord: "ABORT",
                           prompt: "Type SAVED once the kit is stored outside this Mac (or ABORT): ") else {
        EmergencyKitBuilder.discard(paths: paths)
        print("Aborted. The kit was erased and nothing was configured.")
        return
    }
    if !FileManager.default.fileExists(atPath: kit.file.path) {
        print("The kit was moved out of its folder. Make sure no copy stays on this Mac (check Desktop and Downloads).")
    }
    let key = try EmergencyKitBuilder.finalize(kit, paths: paths, replace: replace)
    print("\nEmergency key configured: \(key.fingerprint)")
    print("The copy of the kit on this Mac was erased.")
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    if let previous, previous != key {
        print("""
        Your servers still trust the previous emergency key (\(previous.fingerprint)).
        Run `\(tool) authorize` again for each server, then remove the old key's line
        from their ~/.ssh/authorized_keys.
        """)
    }
}

/// Shows a generated passphrase once and asks the user to retype it exactly.
func showGeneratedPassphrase() -> String? {
    let passphrase = Passphrase.generate()
    print("""

    Your emergency passphrase (shown only this once):

        \(passphrase)

    Save it now in your password manager, or write it down. It is all
    lowercase and the dashes are part of it.

    """)
    for attempt in 1...3 {
        guard let typed = Terminal.askHidden("Retype the passphrase to confirm you saved it: ") else { return nil }
        if typed.trimmingCharacters(in: .whitespaces) == passphrase {
            Terminal.clearScreen()
            print("Passphrase confirmed.")
            return passphrase
        }
        print(attempt < 3 ? "That does not match. Type it exactly, with the dashes." : "That does not match.")
    }
    Terminal.clearScreen()
    return nil
}

func askOwnPassphrase() -> String? {
    print("Choose a passphrase of at least \(Passphrase.minimumCustomLength) characters, different from your Mac password.")
    for _ in 1...3 {
        guard let first = Terminal.askHidden("Passphrase: "), let second = Terminal.askHidden("Repeat it: ") else { return nil }
        if first != second {
            print("The passphrases do not match.")
        } else if first.count < Passphrase.minimumCustomLength {
            print("Too short: use at least \(Passphrase.minimumCustomLength) characters.")
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
    print("Emergency key imported: \(key.fingerprint) (\(key.type))")
    print("Only the public key was copied; keep the private key where it is, outside this Mac.")
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    if let previous, previous != key {
        print("Run `\(tool) authorize` again for each server to install the new emergency key, then remove the old one (\(previous.fingerprint)).")
    }
}

func recovery(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let (positional, options) = try parseOptions(arguments.dropFirst(), booleans: ["replace", "own-passphrase"])
    switch arguments.first {
    case "create":
        try createEmergencyKit(paths: paths, replace: options["replace"] != nil, ownPassphrase: options["own-passphrase"] != nil)
    case "import":
        guard positional.count == 1 else { throw UsageError(description: "usage: \(tool) recovery import FILE.pub [--replace]") }
        try importEmergencyKey(positional[0], paths: paths, replace: options["replace"] != nil)
    case "pubkey":
        guard let key = try RecoveryStore.load(from: paths) else {
            throw UsageError(description: "no emergency key yet. Run `\(tool) setup`.")
        }
        print(key.line)
    default:
        throw UsageError(description: "usage: \(tool) recovery create|import|pubkey")
    }
}

// MARK: - setup

func setup(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    try Terminal.requireInteractive("setup")
    let (_, options) = try parseOptions(arguments)

    Terminal.heading("Step 1 of 3: Touch ID key")
    if let identity = try IdentityStore.load(from: paths) {
        print("Already created: \(identity.fingerprint) (\(identity.comment))")
    } else {
        let policyName = options["biometry"] ?? BiometryPolicy.currentSet.rawValue
        guard let policy = BiometryPolicy(rawValue: policyName) else {
            throw UsageError(description: "--biometry must be current-set or any")
        }
        let identity = try IdentityStore.create(in: paths, policy: policy,
                                                comment: options["comment"] ?? IdentityStore.defaultComment())
        print("Created in the Secure Enclave (policy: \(policy.rawValue)): \(identity.fingerprint)")
    }

    Terminal.heading("Step 2 of 3: backup folder")
    if let folder = SettingsStore.load(from: paths).backupDirectory {
        print("Already set: \(paths.displayPath(folder)). Change it with `\(tool) set backup-path DIR`.")
    } else {
        try askBackupFolder(paths: paths)
    }
    if Command.find("age") == nil {
        print("Warning: age is not installed. Install it with `brew install age` so the inventory backup can be written.")
    }

    Terminal.heading("Step 3 of 3: emergency kit")
    if let key = try RecoveryStore.load(from: paths) {
        print("Already configured: \(key.fingerprint). Replace it with `\(tool) recovery create --replace`.")
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

    Terminal.heading("Next steps")
    print("""
    1. Install the agent if you have not yet:   \(tool) install
    2. Authorize each server (adds both keys and updates the inventory):
           \(tool) authorize user@server -p PORT
    3. Check everything at any time:            \(tool) status
    """)
}

func askBackupFolder(paths: AgentPaths) throws {
    print("""
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
            print("Without a backup folder the inventory only lives on this Mac and is lost with it.")
            if Terminal.confirm(word: "SKIP", cancelWord: "BACK", prompt: "Type SKIP to continue without one (or BACK to choose a folder): ") {
                print("Skipped. Set it later with `\(tool) set backup-path DIR`.")
                return
            }
            continue
        }
        guard let folder = answer.isEmpty ? suggestion : answer else {
            print("Type a folder path, or 'skip'.")
            continue
        }
        do {
            try setBackupFolder(folder, paths: paths)
            return
        } catch {
            print("\(error)")
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
    let usageText = "usage: \(tool) authorize [user@]host [-p PORT] [-F SSH_CONFIG] [--alias NAME] [-- EXTRA_SSH_ARGS]"
    var destination: String?
    var port: Int?
    var configFile: String?
    var alias: String?
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
    let keys = [AuthorizedKey.login(identity), AuthorizedKey.recovery(recoveryKey)]
    print("""
    Authorizing \(resolved.user)@\(resolved.hostname):\(resolved.port)
      Touch ID key   \(identity.fingerprint)
      emergency key  \(recoveryKey.fingerprint)
    """)

    Terminal.heading("1/3 Adding the keys (with your current access to the server)")
    let report = try RemoteKeys.install(keys, on: target)
    for key in keys {
        print("  \(key.label == "login" ? "Touch ID key " : "emergency key"): \(report[key.label] == true ? "added" : "already there")")
    }

    Terminal.heading("2/3 Checking the Touch ID key (approve the Touch ID prompt)")
    let check = RemoteKeys.verifyLogin(on: SSHTarget(destination: destination, port: port, configFile: configFile),
                                       paths: paths, identity: identity)
    print("  \(describe(check))")

    Terminal.heading("3/3 Updating the inventory")
    var inventory = try InventoryStore.load(from: paths)
    inventory.mac = IdentityStore.defaultComment()
    inventory.upsert(InventoryEntry(
        alias: alias ?? destination, destination: destination,
        hostname: resolved.hostname, user: resolved.user, port: resolved.port, sshConfigFile: configFile,
        loginKeyFingerprint: identity.fingerprint, recoveryKeyFingerprint: recoveryKey.fingerprint,
        authorizedAt: .wholeSecondsNow
    ))
    try InventoryStore.save(inventory, to: paths)
    print("  \(alias ?? destination) saved (\(inventory.servers.count) server\(inventory.servers.count == 1 ? "" : "s") in the inventory).")
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)

    guard check == .ok else { exit(1) }
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
    let wanted = Set(arguments)
    var inventory = try InventoryStore.load(from: paths)
    let entries = inventory.servers.filter { wanted.isEmpty || wanted.contains($0.alias) }
    guard !entries.isEmpty else {
        print(inventory.servers.isEmpty
            ? "The inventory is empty. Add servers with `\(tool) authorize`."
            : "No server named \(wanted.sorted().joined(separator: ", ")) in the inventory.")
        return
    }
    let identity = requireIdentity(paths)
    let recoveryKey = try requireRecoveryKey(paths)
    let keys = [AuthorizedKey.login(identity), AuthorizedKey.recovery(recoveryKey)]

    print("Checking \(entries.count) server\(entries.count == 1 ? "" : "s"); each one asks for Touch ID.")
    var problems = 0
    for entry in entries {
        print("\n\(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
        let target = SSHTarget(destination: entry.destination, port: entry.port, configFile: entry.sshConfigFile)
        let outcome = RemoteKeys.audit(target, keys: keys, paths: paths, identity: identity)
        let result = auditSummary(outcome)
        print("  \(result.ok ? "✓" : "✗") \(result.text)")
        if !result.ok { problems += 1 }
        if let index = inventory.servers.firstIndex(where: { $0.alias == entry.alias }) {
            inventory.servers[index].lastAudit = .wholeSecondsNow
            inventory.servers[index].lastAuditResult = result.text
        }
    }
    try InventoryStore.save(inventory, to: paths)
    reportBackup(InventoryBackup.export(paths: paths), paths: paths)
    print(problems == 0 ? "\nAll servers have both keys." : "\n\(problems) server\(problems == 1 ? "" : "s") need attention: run `\(tool) authorize` for them.")
    if problems > 0 { exit(1) }
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
        print("The inventory is empty. Add servers with `\(tool) authorize`.")
        return
    }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    for entry in inventory.servers {
        let audited = entry.lastAudit.map { "audited \(formatter.string(from: $0)): \(entry.lastAuditResult ?? "")" } ?? "never audited"
        print("\(entry.alias)\t\(entry.user)@\(entry.hostname):\(entry.port)\tauthorized \(formatter.string(from: entry.authorizedAt))\t\(audited)")
    }
}

// MARK: - status additions

func recoveryStatus(paths: AgentPaths) {
    do {
        if let key = try RecoveryStore.load(from: paths) {
            print("Emergency key:  \(key.fingerprint) (\(key.type))")
        } else {
            print("Emergency key:  none — run `\(tool) setup`")
        }
    } catch {
        print("Emergency key:  error — \(error)")
    }

    let settings = SettingsStore.load(from: paths)
    if let folder = settings.backupDirectory {
        let backup = folder.appendingPathComponent(InventoryBackup.fileName)
        if !FileManager.default.fileExists(atPath: folder.path) {
            print("Backup folder:  \(paths.displayPath(folder)) — MISSING")
        } else if let modified = (try? FileManager.default.attributesOfItem(atPath: backup.path))?[.modificationDate] as? Date {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm"
            print("Backup folder:  \(paths.displayPath(folder)) (inventory.age updated \(formatter.string(from: modified)))")
        } else {
            print("Backup folder:  \(paths.displayPath(folder)) (no inventory.age yet)")
        }
    } else {
        print("Backup folder:  not set — `\(tool) set backup-path DIR`")
    }
    if Command.find("age") == nil {
        print("age:            not installed — `brew install age` (needed for the inventory backup)")
    }

    let count = (try? InventoryStore.load(from: paths).servers.count) ?? 0
    print("Inventory:      \(count) server\(count == 1 ? "" : "s")")

    let fileVault = (try? Command.run("/usr/bin/fdesetup", ["status"]))?.stdoutText ?? ""
    if fileVault.contains("FileVault is On") {
        print("FileVault:      on")
    } else {
        print("FileVault:      OFF — turn it on (System Settings > Privacy & Security) to protect the local inventory")
    }
}

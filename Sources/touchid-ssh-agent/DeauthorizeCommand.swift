import Foundation
import TouchIDSSHCore

/// A server to take this Mac's keys off: an inventory entry, or a destination
/// typed by the user that the inventory does not list.
struct DeauthorizeTarget {
    var label: String
    var entry: InventoryEntry?
    var target: SSHTarget
}

/// `deauthorize NAME... | --all`: removes this Mac's Touch ID key and emergency
/// key from servers, matched exactly by key, and drops them from the inventory.
/// `--force NAME...` only drops them, for servers this Mac can no longer reach.
func deauthorize(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let usageText = """
    usage: \(tool) deauthorize NAME... | --all [-F SSH_CONFIG] [-p PORT] [-- SSH_ARGS]
           \(tool) deauthorize --force NAME...
    """
    var names: [String] = []
    var all = false
    var force = false
    var configFile: String?
    var port: Int?
    var extra: [String] = []
    var iterator = arguments.makeIterator()
    while let argument = iterator.next() {
        switch argument {
        case "--all":
            all = true
        case "--force":
            force = true
        case "-F":
            guard let value = iterator.next() else { throw UsageError(description: usageText) }
            configFile = (value as NSString).expandingTildeInPath
        case "-p":
            guard let value = iterator.next(), let number = Int(value) else { throw UsageError(description: usageText) }
            port = number
        case "--":
            while let rest = iterator.next() { extra.append(rest) }
        default:
            guard !argument.hasPrefix("-") else { throw UsageError(description: usageText) }
            names.append(argument)
        }
    }
    guard all ? names.isEmpty : !names.isEmpty else { throw UsageError(description: usageText) }
    if force {
        guard !all else {
            throw UsageError(description: "--force forgets only the servers you name; it does not take --all.\n\(usageText)")
        }
        guard configFile == nil, port == nil, extra.isEmpty else {
            throw UsageError(description: "--force contacts no server, so -F, -p and ssh options do not apply.\n\(usageText)")
        }
        // Before loading the keys: an entry is forgotten even when this Mac has none left.
        return try forget(names, paths: paths)
    }
    try Terminal.requireInteractive("deauthorize")

    let identity = try IdentityStore.load(from: paths)
    let emergency = try RecoveryStore.load(from: paths)
    let ca = try CertificateAuthorityStore.load(from: paths)
    // The CA is matched by its key alone: every line holding it goes, whatever its options.
    let keys = (identity.map { [AuthorizedKey.login($0)] } ?? []) + (emergency.map { [AuthorizedKey.recovery($0)] } ?? [])
        + (ca.map { [AuthorizedKey(label: CATrust.label, type: SSHKeyFormat.keyType, blob: $0.publicKeyBlob, comment: $0.comment)] } ?? [])
    guard !keys.isEmpty else {
        throw UsageError(description: "this Mac has no Touch ID key and no emergency key, so there is nothing to remove.")
    }

    var inventory = try InventoryStore.load(from: paths)
    var targets: [DeauthorizeTarget] = []
    if all {
        guard !inventory.servers.isEmpty else {
            throw UsageError(description: "the inventory is empty. Name a server instead: `\(tool) deauthorize user@host`.")
        }
        targets = inventory.servers.map { deauthorizeTarget(for: $0, configFile: configFile, extra: extra) }
    } else {
        for name in names {
            if let found = inventory.servers.first(where: {
                $0.alias == name || $0.destination == name || "\($0.user)@\($0.hostname)" == name
            }) {
                targets.append(deauthorizeTarget(for: found, configFile: configFile, extra: extra))
            } else {
                targets.append(DeauthorizeTarget(label: name, entry: nil, target: SSHTarget(
                    destination: name, port: port, configFile: configFile, bootstrapArguments: extra)))
            }
        }
    }

    Out.header("deauthorize", all ? "remove this Mac's keys from every server" : "remove this Mac's keys from a server")
    Out.say("This removes these keys from each server's authorized_keys, matched exactly:")
    if let identity { Out.say("  Touch ID key    \(identity.fingerprint)") }
    if let emergency { Out.say("  Emergency key   \(emergency.fingerprint)") }
    if let ca { Out.say("  Temporary CA    \(ca.fingerprint) (lines trusting it for temporary access)") }
    Out.say("""

    Other keys on the server are not touched, and the server leaves the inventory.
    Each server is reached with your usual ssh access (one Touch ID when that goes
    through this agent; add ssh options after -- to use another key).
    """)
    Out.section("Servers")
    for item in targets {
        Out.say("  • \(item.label)" + (item.entry.map { "  (\($0.user)@\($0.hostname):\($0.port))" } ?? "  (not in the inventory)"))
        if let entry = item.entry,
           entry.loginKeyFingerprint != identity?.fingerprint || entry.recoveryKeyFingerprint != emergency?.fingerprint {
            Out.say("    ! the inventory recorded other keys for it; only this Mac's current keys are removed")
        }
    }
    guard Terminal.confirm(word: "REMOVE", cancelWord: "ABORT",
                           prompt: "Type REMOVE to take this Mac's keys off \(targets.count) server\(targets.count == 1 ? "" : "s") (or ABORT): ") else {
        Out.say("Aborted. No server was changed.")
        return
    }

    var removed: [InventoryEntry] = []
    var failed: [String] = []
    for item in targets {
        Out.say("\n\(item.label)")
        if let text = removeKeys(keys + pendingOldCA(item.entry), from: item) {
            Out.say("  ✓ \(text)")
            if let entry = item.entry { removed.append(entry) }
        } else {
            failed.append(item.label)
        }
    }

    if !removed.isEmpty {
        inventory = try InventoryStore.update(paths) { current -> Inventory in
            current.servers.removeAll { entry in removed.contains { $0.alias == entry.alias } }
            return current
        }
        Out.say("")
        Out.say("Inventory: \(removed.count) server\(removed.count == 1 ? "" : "s") removed, \(inventory.servers.count) left.")
        reportBackup(InventoryBackup.export(paths: paths, allowEmpty: inventory.servers.isEmpty), paths: paths)
        for entry in removed where sshConfigStatus(for: entry, paths: paths).ok {
            Out.say("! ssh config: a Host block for \(entry.alias) still points to the Touch ID agent. Remove it if you no longer use it.")
        }
    }

    if all, failed.isEmpty, identity != nil {
        Out.section("This Mac")
        Out.say("""
        No server in the inventory trusts this Mac's keys any more. To start over,
        you can also delete this Mac's Touch ID key: `\(tool) setup` then
        creates a new one. The emergency key stays configured: `authorize` installs
        it again, and `\(tool) recovery create --replace` makes a new kit.
        """)
        if Terminal.ask("Type DELETE to delete the Touch ID key (or press Enter to keep it): ")?
            .trimmingCharacters(in: .whitespaces) == "DELETE" {
            try IdentityStore.delete(from: paths)
            Out.say("  Touch ID key deleted.")
        } else {
            Out.say("  Kept.")
        }
    }

    if !failed.isEmpty {
        Out.say("""

        \(failed.count) server\(failed.count == 1 ? " was" : "s were") left as \(failed.count == 1 ? "it was" : "they were"): \(failed.joined(separator: ", ")).
        """)
        if targets.contains(where: { $0.entry != nil && failed.contains($0.label) }) {
            Out.say("If you can no longer log in to one of them, `\(tool) deauthorize --force NAME` drops it from the inventory without contacting it.")
        }
        exit(1)
    }
}

/// `deauthorize --force NAME...`: drops every inventory entry that names a
/// server, and updates the backup, without contacting the server. Its keys stay
/// there, so the summary lists them for when access comes back.
private func forget(_ names: [String], paths: AgentPaths) throws {
    let inventory = try InventoryStore.load(from: paths)
    var entries: [InventoryEntry] = []
    for name in names {
        // Every account on a host typed by its name: all of them point to the lost server.
        let found = inventory.servers.filter {
            $0.alias == name || $0.destination == name || $0.hostname == name || "\($0.user)@\($0.hostname)" == name
        }
        guard !found.isEmpty else {
            throw UsageError(description: "\(name) is not in the inventory, so there is nothing to forget. `\(tool) inventory` lists the servers.")
        }
        entries += found.filter { entry in !entries.contains { $0.alias == entry.alias } }
    }
    try Terminal.requireInteractive("deauthorize")

    Out.header("deauthorize", "forget servers this Mac can no longer reach")
    Out.say("""
    This drops these servers from the inventory and its encrypted backup without
    contacting them. Nothing changes on the servers: the keys listed below stay in
    their authorized_keys, and the emergency kit still opens them while its key is
    there. Use it only for a server you can no longer log in to.
    """)
    Out.section("Servers")
    for entry in entries {
        Out.say("  • \(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port))")
        Out.say("      Touch ID key    \(entry.loginKeyFingerprint)")
        Out.say("      Emergency key   \(entry.recoveryKeyFingerprint)")
        for ca in entry.temporaryAccess?.recordedCAs ?? [] { Out.say("      Temporary CA    \(ca.fingerprint)") }
    }
    guard Terminal.confirm(word: "FORGET", cancelWord: "ABORT",
                           prompt: "Type FORGET to drop \(entries.count) server\(entries.count == 1 ? "" : "s") from the inventory without touching \(entries.count == 1 ? "it" : "them") (or ABORT): ") else {
        Out.say("Aborted. The inventory was not changed.")
        return
    }

    let left = try InventoryStore.update(paths) { current -> Int in
        current.servers.removeAll { entry in entries.contains { $0.alias == entry.alias } }
        return current.servers.count
    }
    Out.say("")
    Out.say("Inventory: \(entries.count) server\(entries.count == 1 ? "" : "s") removed, \(left) left.")
    reportBackup(InventoryBackup.export(paths: paths, allowEmpty: left == 0), paths: paths)
    for entry in entries {
        // The grant's targets are frozen in its own files, so it keeps working until it ends.
        if let grant = entry.temporaryAccess?.lastGrant, grant.endedAt == nil, grant.expiresAt > Date() {
            Out.say("! \(entry.alias) is in a temporary grant valid until \(localTime(grant.expiresAt)); `\(tool) access stop` ends it now.")
        }
        if sshConfigStatus(for: entry, paths: paths).ok {
            Out.say("! ssh config: a Host block for \(entry.alias) still points to the Touch ID agent. Remove it if you no longer use it.")
        }
    }
    let one = entries.count == 1
    Out.say("""

    The keys above are still on \(one ? "that server" : "those servers"). If you get access back,
    this takes this Mac's keys off \(one ? "it" : "them"):
    """)
    for entry in entries {
        Out.say("    \(tool) deauthorize \(entry.user)@\(entry.hostname)" + (entry.port == 22 ? "" : " -p \(entry.port)"))
    }
    Out.say("""
    From a server's console, `ssh-keygen -lf ~/.ssh/authorized_keys` shows the
    fingerprint of each line, to remove them by hand.
    """)
}

/// A lost Mac's CA still waiting for removal on this server (an unfinished
/// recovery): it goes too, matched by its recorded key.
private func pendingOldCA(_ entry: InventoryEntry?) -> [AuthorizedKey] {
    guard let rotation = entry?.temporaryAccess?.caRotation else { return [] }
    return rotation.oldCAs.compactMap(\.blob).enumerated().map { index, blob in
        AuthorizedKey(label: index == 0 ? "old-ca" : "old-ca-\(index + 1)",
                      type: SSHKeyFormat.keyTypeName(ofBlob: blob) ?? SSHKeyFormat.keyType, blob: blob, comment: "old-ca")
    }
}

private func deauthorizeTarget(for entry: InventoryEntry, configFile: String?, extra: [String]) -> DeauthorizeTarget {
    DeauthorizeTarget(label: entry.alias, entry: entry, target: SSHTarget(
        destination: entry.destination, port: entry.port, configFile: configFile ?? entry.sshConfigFile,
        bootstrapArguments: extra))
}

/// Runs the removal on one server. Returns what was done, or nil (after saying
/// why) when the server was left unchanged.
private func removeKeys(_ keys: [AuthorizedKey], from item: DeauthorizeTarget) -> String? {
    func attempt(allowEmpty: Bool) -> (report: [String: String], output: String)? {
        guard let result = try? RemoteKeys.runWithUserAccess(RemoteKeys.deauthorizeScript(keys, allowEmpty: allowEmpty), on: item.target),
              result.ok else {
            Out.say("  ✗ could not log in or run the change there; nothing was changed")
            return nil
        }
        return (RemoteKeys.parse(result.output), result.output)
    }
    guard var outcome = attempt(allowEmpty: false) else { return nil }
    if outcome.report["empty"] == "refused" {
        Out.say("""
          ! No other key would be left on it: afterwards only a password, or your
            provider's console, gets you in.
        """)
        guard Terminal.confirm(word: "REMOVE", cancelWord: "SKIP", prompt: "Type REMOVE to remove the keys anyway (or SKIP): ") else {
            Out.say("  ✗ skipped; nothing was changed")
            return nil
        }
        guard let forced = attempt(allowEmpty: true) else { return nil }
        outcome = forced
    }

    let left = RemoteKeys.listedLines(outcome.output).compactMap { RemoteKeys.keyBlob(inAuthorizedKeysLine: $0) }
    guard keys.allSatisfy({ outcome.report[$0.label] != nil }), RemoteKeys.containsListing(outcome.output),
          !left.contains(where: { blob in keys.contains { $0.blob == blob } }) else {
        Out.say("  ✗ the server did not confirm the change; check its ~/.ssh/authorized_keys")
        return nil
    }
    let names = ["login": "the Touch ID key", "recovery": "the emergency key", CATrust.label: "the CA trust"]
    let found = keys.filter { outcome.report[$0.label] == "found" }
        .compactMap { names[$0.label] ?? ($0.label.hasPrefix("old-ca") ? "a previous CA's trust" : nil) }
    let others = left.isEmpty ? "no other key left" : "\(left.count) other key\(left.count == 1 ? "" : "s") left"
    let caNote = keys.contains { $0.label == CATrust.label } && outcome.report[CATrust.label] == "found"
        ? " Trust configured elsewhere (for example TrustedUserCAKeys in sshd_config) is not checked." : ""
    return found.isEmpty
        ? "none of this Mac's keys was there; \(others)"
        : "removed \(listed(found)); \(others).\(caNote)"
}

/// "a", "a and b", "a, b and c".
func listed(_ items: [String]) -> String {
    guard items.count > 1 else { return items.first ?? "" }
    return items.dropLast().joined(separator: ", ") + " and " + items[items.count - 1]
}

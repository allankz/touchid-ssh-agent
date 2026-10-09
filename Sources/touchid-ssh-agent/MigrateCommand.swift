import Foundation
import TouchIDSSHCore

/// `migrate`: shows, with this Mac's own data, how to move to a new Mac and
/// what to fix first. It changes nothing and logs in nowhere.
func migrate(paths: AgentPaths) throws {
    Out.header("migrate", "how to move to a new Mac; nothing changes")
    let identity = try IdentityStore.load(from: paths)
    let emergency = try RecoveryStore.load(from: paths)
    let settings = SettingsStore.load(from: paths)
    let inventory = try InventoryStore.load(from: paths)
    guard identity != nil || !inventory.servers.isEmpty else {
        Out.say("Nothing to move yet: this Mac has no Touch ID key. Start with `\(tool) setup`.")
        return
    }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm"

    Out.section("Today")
    Out.say("  Touch ID key    \(identity?.fingerprint ?? "none")")
    Out.say("                  Lives only in this Mac's Secure Enclave and cannot be copied.")
    Out.say("  Emergency key   \(emergency?.fingerprint ?? "none")")
    Out.say("                  Its kit is the emergency-kit.txt file you saved off this Mac.")
    let backup = settings.backupDirectory?.appendingPathComponent(InventoryBackup.fileName)
    let backupDate = backup.flatMap { (try? FileManager.default.attributesOfItem(atPath: $0.path))?[.modificationDate] as? Date }
    if let folder = settings.backupDirectory {
        Out.say("  Backup folder   \(paths.displayPath(folder))")
        Out.say("                  " + (backupDate.map { "inventory.age updated \(formatter.string(from: $0))" } ?? "no inventory.age yet"))
    } else {
        Out.say("  Backup folder   none")
    }
    Out.say("  Servers         \(inventory.servers.count)")
    for entry in inventory.servers {
        let audited = entry.lastAudit.map { "audited \(formatter.string(from: $0))" } ?? "never audited"
        Out.say("    • \(entry.alias)  (\(entry.user)@\(entry.hostname):\(entry.port)), \(audited)")
    }

    // Everything recover will need on the new Mac.
    var warnings: [String] = []
    if emergency == nil {
        warnings.append("No emergency key: the new Mac could not open your servers. Run `\(tool) setup`, then `authorize` each server again.")
    }
    if let folder = settings.backupDirectory {
        let path = folder.standardizedFileURL.path
        if !FileManager.default.fileExists(atPath: path) {
            warnings.append("The backup folder does not exist any more. Choose one with `\(tool) set backup-path DIR`.")
        } else if !["/Library/CloudStorage/", "/Library/Mobile Documents/", "/Dropbox/"].contains(where: path.contains) {
            warnings.append("Make sure \(paths.displayPath(folder)) syncs to the cloud: the new Mac reads inventory.age from it.")
        }
        if backupDate == nil {
            warnings.append("No inventory.age yet. Run `\(tool) audit` to write it.")
        } else if let backupDate, inventory.updatedAt.timeIntervalSince(backupDate) > 1 {
            warnings.append("inventory.age is older than this Mac's inventory. Run `\(tool) audit` to update it.")
        }
    } else {
        warnings.append("No backup folder: the new Mac would not find your server list. Set one with `\(tool) set backup-path DIR`.")
    }
    if Command.find("age") == nil {
        warnings.append("age is not installed, so the backup cannot be updated: `brew install age`.")
    }
    for entry in inventory.servers {
        if let identity, entry.loginKeyFingerprint != identity.fingerprint {
            warnings.append("\(entry.alias) lists another Touch ID key. Run `\(tool) authorize \(entry.destination)` again.")
        }
        if let emergency, entry.recoveryKeyFingerprint != emergency.fingerprint {
            warnings.append("\(entry.alias) was authorized with another emergency key. Run `\(tool) authorize \(entry.destination)` again.")
        }
        if entry.hostKeys?.isEmpty ?? true {
            warnings.append("\(entry.alias) has no host key recorded, so recover would trust whatever key it presents. "
                + "Run `\(tool) audit \(entry.alias)` to record the one ssh trusts.")
        }
    }

    Out.section("Before you switch")
    if warnings.isEmpty {
        Out.say("  ✓ Everything the new Mac needs is in place.")
    } else {
        for warning in warnings { Out.say("  ! \(warning)") }
    }
    Out.say("""

      1. Find the emergency kit file and its passphrase, and check that they still
         open every server (this changes nothing):
             \(tool) recovery test emergency-kit.txt
      2. Keep using this Mac as usual. Nothing changes on the servers until you
         run recover on the new Mac.
    """)

    Out.section("On the new Mac")
    Out.say("""
      1. Sign in to your cloud service, so the backup folder syncs\(settings.backupDirectory == nil ? "" : " (it holds inventory.age)").
      2. Install touchid-ssh-agent:
             git clone https://github.com/allankz/touchid-ssh-agent
             cd touchid-ssh-agent && make install
      3. Move the servers:
             \(tool) recover emergency-kit.txt
         It asks for the kit's passphrase twice, checks every server and asks
         whether to replace the emergency key. Then it installs the new Mac's
         keys, removes this Mac's key, starts the agent, offers the ssh config
         blocks and finishes with an audit.
    """)

    Out.section("Back on this Mac, afterwards")
    Out.say("""
      recover took this Mac's key off the servers, so it no longer logs in. To clean up:
             \(tool) uninstall
             rm -rf \(Terminal.shellQuoted(paths.displayPath(paths.directory)))
      and remove the Host blocks from ~/.ssh/config if you will not ssh from this Mac.
    """)
}

import Foundation
import TouchIDSSHCore

/// The CA side of `recover`: servers enrolled for temporary access trust the
/// lost Mac's CA. Each one gets this Mac's CA with the same principal and
/// restrictions, a certificate login through it is verified, and only then
/// is the lost Mac's CA removed, by the exact key the inventory recorded.
/// Progress is saved in the local inventory before every server change, so an
/// interrupted run resumes without forgetting which old CA still has to go.
final class RecoveryCA {
    let ca: StoredIdentity
    let created: Bool
    let paths: AgentPaths
    let recoveryId: String
    private var validation: CertificateValidation?
    private var validationFailed: String?
    private var principals: [String] = []
    private var users = Set<String>()

    init(paths: AgentPaths, created: Bool, ca: StoredIdentity) {
        self.paths = paths
        self.ca = ca
        self.created = created
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        recoveryId = "recover-\(formatter.string(from: Date()))"
    }

    deinit { validation?.stop() }

    /// True when `local` (this Mac's inventory) shows the server's CA work done.
    func isComplete(_ local: InventoryEntry?) -> Bool {
        guard let enrollment = local?.temporaryAccess else { return false }
        return enrollment.caFingerprint == ca.fingerprint && enrollment.caRotation == nil && enrollment.verified
    }

    /// The rotation record for one server, built from the decrypted inventory.
    func rotation(for old: InventoryEntry, step: CARotation.Step = .planned) -> CARotation? {
        guard let enrollment = old.temporaryAccess else { return nil }
        return CARotation(recoveryId: recoveryId, oldCAPublicKey: enrollment.caPublicKey, oldCAFingerprint: enrollment.caFingerprint,
                          newCAPublicKey: ca.authorizedKeyLine, newCAFingerprint: ca.fingerprint, principal: enrollment.principal,
                          authorizedKeyOptions: CATrust.safeOptions(enrollment.authorizedKeyOptions, principal: enrollment.principal),
                          step: step, updatedAt: .wholeSecondsNow)
    }

    /// Before anything changes: every enrolled server that still needs work
    /// gets a pending rotation in this Mac's inventory. A resumed run keeps the
    /// record it finds.
    func recordIntent(for servers: [InventoryEntry]) throws {
        try InventoryStore.update(paths) { inventory in
            for old in servers {
                guard let rotation = rotation(for: old) else { continue }
                if let index = inventory.servers.firstIndex(where: { $0.isSameServer(as: old) }) {
                    guard !isComplete(inventory.servers[index]) else { continue }
                    principals.append(rotation.principal)
                    users.insert(old.user)
                    if inventory.servers[index].temporaryAccess == nil { inventory.servers[index].temporaryAccess = old.temporaryAccess }
                    if inventory.servers[index].temporaryAccess?.caRotation == nil {
                        inventory.servers[index].temporaryAccess?.caRotation = rotation
                    }
                } else {
                    principals.append(rotation.principal)
                    users.insert(old.user)
                    var copy = old
                    copy.temporaryAccess?.lastGrant = nil
                    copy.temporaryAccess?.caRotation = rotation
                    inventory.upsert(copy)
                }
            }
        }
    }

    func record(_ step: CARotation.Step, for old: InventoryEntry) {
        try? InventoryStore.update(paths) { inventory in
            for index in inventory.servers.indices where inventory.servers[index].isSameServer(as: old) {
                inventory.servers[index].temporaryAccess?.caRotation?.step = step
                inventory.servers[index].temporaryAccess?.caRotation?.updatedAt = .wholeSecondsNow
            }
        }
    }

    /// One validation certificate for every enrolled server of this run (one
    /// Touch ID). It grants nothing, lives only in memory and in a temporary
    /// directory, and is signed again only if it expires mid-run.
    func validationCredential() -> (credential: CertificateValidation?, error: String?) {
        if let validation, !validation.isExpired { return (validation, nil) }
        if let validationFailed { return (nil, validationFailed) }
        validation?.stop()
        Out.say("""
          Touch ID: approve a short-lived validation certificate from this Mac's CA. It grants
          nothing and is never saved; it only checks that each server accepts the new CA
          before the lost Mac's CA is removed.
        """)
        do {
            validation = try makeValidation(ca: ca, principals: Array(Set(principals)).sorted(), users: users, lifetime: 1800,
                                            paths: paths, purpose: "check temporary SSH access on \(Set(principals).count) "
                                                + "server\(Set(principals).count == 1 ? "" : "s") after recovery (nothing is granted)")
            return (validation, nil)
        } catch let error as SignError {
            validationFailed = "the validation certificate was not signed: \(error.description)"
        } catch {
            validationFailed = "could not sign a validation certificate: \(error)"
        }
        return (nil, validationFailed)
    }

    func stop() { validation?.stop() }
}

import Foundation
import TouchIDSSHCore

/// The CA side of `recover`: servers enrolled for temporary access trust the
/// lost Mac's CA. Each one gets this Mac's CA with the same principal and
/// restrictions, and every CA of the lost Mac is removed by the exact key the
/// inventory recorded, once the new Touch ID login works. Its private key is on
/// the lost Mac, so keeping it would help nobody but whoever has that Mac. A
/// certificate login through the new CA is checked too; when it fails, the
/// server stays unconfirmed for temporary access (`authorize --temporary-access`
/// finishes it) instead of keeping any old credential. Progress is saved in the
/// local inventory before every server change.
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

    /// The lost Mac's CAs that `old` (from the decrypted backup) records: its
    /// enrolled CA and, when the lost Mac left a replacement unfinished, that
    /// replacement's CAs. Never this Mac's CA. Records whose key and
    /// fingerprint disagree are returned apart: they can only be removed by hand.
    func oldCAs(for old: InventoryEntry) -> (valid: [CAKey], damaged: [CAKey]) {
        guard let enrollment = old.temporaryAccess else { return ([], []) }
        let keys = enrollment.recordedCAs.filter { $0.fingerprint != ca.fingerprint }
        return (keys.filter { $0.blob != nil }, keys.filter { $0.blob == nil })
    }

    /// This Mac's own enrollment of the server, if `local` has one (for example
    /// from an `authorize --temporary-access` run before `recover`).
    func ownEnrollment(_ local: InventoryEntry?) -> TemporaryAccessEnrollment? {
        guard let enrollment = local?.temporaryAccess, enrollment.caFingerprint == ca.fingerprint else { return nil }
        return enrollment
    }

    /// True when this Mac's inventory shows the server's CA work done: this
    /// Mac's CA recorded, no replacement pending, and every CA of the lost Mac
    /// recorded as removed. A new CA still awaiting confirmation counts as done:
    /// that is `authorize --temporary-access`'s job, not recover's.
    func isComplete(_ local: InventoryEntry?, old: InventoryEntry) -> Bool {
        guard let enrollment = ownEnrollment(local), enrollment.caRotation == nil else { return false }
        let (valid, damaged) = oldCAs(for: old)
        let retired = Set(enrollment.retiredCAFingerprints ?? [])
        return damaged.isEmpty && valid.allSatisfy { retired.contains($0.fingerprint) }
    }

    /// The replacement record for one server. The principal and restrictions
    /// come from this Mac's own enrollment when there is one, otherwise from
    /// the lost Mac's.
    func rotation(for old: InventoryEntry, local: InventoryEntry?, step: CARotation.Step = .planned) -> CARotation? {
        guard let enrollment = old.temporaryAccess else { return nil }
        let (valid, damaged) = oldCAs(for: old)
        let all = valid + damaged
        guard let primary = all.first else { return nil }
        let scope = ownEnrollment(local) ?? enrollment
        var rotation = CARotation(
            recoveryId: recoveryId, oldCAPublicKey: primary.publicKey, oldCAFingerprint: primary.fingerprint,
            newCAPublicKey: ca.authorizedKeyLine, newCAFingerprint: ca.fingerprint, principal: scope.principal,
            authorizedKeyOptions: CATrust.safeOptions(scope.authorizedKeyOptions, principal: scope.principal),
            step: step, updatedAt: .wholeSecondsNow)
        if all.count > 1 { rotation.extraOldCAs = Array(all.dropFirst()) }
        return rotation
    }

    /// Before anything changes: every enrolled server that still needs CA work
    /// gets a pending replacement in this Mac's inventory, naming every old CA
    /// it must lose. A resumed run keeps the record it finds.
    func recordIntent(for pending: [InventoryEntry]) throws {
        try InventoryStore.update(paths) { inventory in
            for old in pending {
                let index = inventory.servers.firstIndex { $0.isSameServer(as: old) }
                let local = index.map { inventory.servers[$0] }
                guard let rotation = rotation(for: old, local: local) else { continue }
                principals.append(rotation.principal)
                users.insert(old.user)
                if let index {
                    if inventory.servers[index].temporaryAccess == nil {
                        var enrollment = old.temporaryAccess
                        enrollment?.lastGrant = nil
                        inventory.servers[index].temporaryAccess = enrollment
                    }
                    if inventory.servers[index].temporaryAccess?.caRotation == nil {
                        inventory.servers[index].temporaryAccess?.caRotation = rotation
                    }
                } else {
                    var copy = old
                    copy.temporaryAccess?.lastGrant = nil
                    copy.temporaryAccess?.caRotation = rotation
                    copy.alias = inventory.uniqueAlias(copy.alias, for: copy)
                    inventory.servers.append(copy)
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

    /// One validation certificate for every server whose CA is checked in
    /// this run (one Touch ID). It grants nothing, lives only in memory and in
    /// a temporary directory, and is signed again only if it expires mid-run.
    /// A denial is remembered, so it is not asked again for every server.
    func validationCredential() -> (credential: CertificateValidation?, error: String?) {
        if let validation, !validation.isExpired { return (validation, nil) }
        if let validationFailed { return (nil, validationFailed) }
        validation?.stop()
        let names = Array(Set(principals)).sorted()
        Out.say("""
          Touch ID: approve a short-lived validation certificate from this Mac's CA. It grants
          nothing and is never saved; it only checks that each server accepts the new CA.
        """)
        do {
            validation = try makeValidation(ca: ca, principals: names, users: users, lifetime: 1800, paths: paths,
                                            purpose: "check temporary SSH access on \(names.count) "
                                                + "server\(names.count == 1 ? "" : "s") after recovery (nothing is granted)")
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

extension Inventory {
    /// `alias`, or `alias-2`, `alias-3`… when another server already uses it,
    /// so saving one server never replaces an unrelated one.
    func uniqueAlias(_ alias: String, for entry: InventoryEntry) -> String {
        var candidate = alias
        var counter = 2
        while servers.contains(where: { $0.alias == candidate && !$0.isSameServer(as: entry) }) {
            candidate = "\(alias)-\(counter)"
            counter += 1
        }
        return candidate
    }
}

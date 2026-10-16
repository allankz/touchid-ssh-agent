import Foundation
import TouchIDSSHCore

/// Touch ID timeout for prompts this command shows itself.
var promptTimeout: TimeInterval {
    ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_PROMPT_TIMEOUT"].flatMap(TimeInterval.init)
        ?? SecureEnclaveSigner.defaultPromptTimeout
}

/// Signs one short-lived validation certificate with the CA (one Touch ID).
/// The certificate grants nothing: it only proves servers accept the CA.
func makeValidation(ca: StoredIdentity, principals: [String], users: Set<String>, lifetime: UInt64,
                    paths: AgentPaths, purpose: String) throws -> CertificateValidation {
    try CertificateValidation(caBlob: ca.publicKeyBlob, principals: principals, users: users, lifetime: lifetime,
                              paths: paths) { data in
        try SecureEnclaveSigner.sign(data, with: ca, reason: purpose, timeout: promptTimeout)
    }
}

/// What `authorize --temporary-access` will install, decided before the
/// server changes: this Mac's CA (created on first use), and the server's
/// stable target ID and principal (reused when it was enrolled before).
struct EnrollmentPlan {
    let ca: StoredIdentity
    let created: Bool
    let targetId: String
    let principal: String
    let key: AuthorizedKey
    let previous: TemporaryAccessEnrollment?

    /// CAs this server trusted before that must be removed once the current
    /// CA works there: a previous CA of this Mac, or a lost Mac's CA left by a
    /// recovery that did not finish. Only records whose key matches their
    /// fingerprint, so nothing else is ever removed.
    var retiring: [CAKey] {
        (previous?.recordedCAs ?? []).filter { $0.fingerprint != ca.fingerprint && $0.blob != nil }
    }

    static func prepare(paths: AgentPaths, resolved: ResolvedTarget, existing: InventoryEntry?) throws -> EnrollmentPlan {
        if let proxy = resolved.proxy {
            throw UsageError(description: """
            this server is reached through \(DisplayText.sanitize(proxy, maxLength: 80)). Temporary access does not
            support jump hosts or proxy commands in this version; authorize a directly reachable address,
            or run authorize without --temporary-access.
            """)
        }
        let (ca, created) = try CertificateAuthorityStore.loadOrCreate(in: paths)
        let previous = existing?.temporaryAccess
        let targetId = previous?.targetId ?? CATrust.newTargetId()
        let principal = previous?.principal ?? CATrust.principal(targetId: targetId)
        return EnrollmentPlan(ca: ca, created: created, targetId: targetId, principal: principal,
                              key: CATrust.authorizedKey(ca: ca, principal: principal), previous: previous)
    }

    /// Before the server changes: record which old CA must go, so an
    /// interruption never loses it.
    func recordIntent(paths: AgentPaths) throws {
        guard let rotation = previous?.caRotation ?? newRotation(step: .planned) else { return }
        try InventoryStore.update(paths) { inventory in
            for index in inventory.servers.indices where inventory.servers[index].temporaryAccess?.targetId == targetId {
                inventory.servers[index].temporaryAccess?.caRotation = rotation
            }
        }
    }

    func newRotation(step: CARotation.Step) -> CARotation? {
        guard let first = retiring.first else { return nil }
        var rotation = CARotation(
            recoveryId: "authorize-\(Int(Date().timeIntervalSince1970))", oldCAPublicKey: first.publicKey,
            oldCAFingerprint: first.fingerprint, newCAPublicKey: ca.authorizedKeyLine, newCAFingerprint: ca.fingerprint,
            principal: principal, authorizedKeyOptions: CATrust.options(principal: principal), step: step,
            updatedAt: .wholeSecondsNow)
        if retiring.count > 1 { rotation.extraOldCAs = Array(retiring.dropFirst()) }
        return rotation
    }

    /// After the keys were added: checks the CA line's scope, then a real
    /// certificate login (one Touch ID for a validation certificate), then
    /// retires an old CA. Returns the enrollment to record.
    func verify(listing: [String], resolved: ResolvedTarget, target: SSHTarget,
                paths: AgentPaths) -> (ok: Bool, enrollment: TemporaryAccessEnrollment, lines: [String]) {
        var enrollment = TemporaryAccessEnrollment(
            targetId: targetId, principal: principal, caPublicKey: ca.authorizedKeyLine, caFingerprint: ca.fingerprint,
            authorizedKeyOptions: CATrust.installedOptions(listing, caBlob: ca.publicKeyBlob) ?? CATrust.options(principal: principal),
            enrolledAt: previous?.caFingerprint == ca.fingerprint ? (previous?.enrolledAt ?? .wholeSecondsNow) : .wholeSecondsNow,
            verified: false)
        enrollment.lastAudit = .wholeSecondsNow
        if previous?.caFingerprint == ca.fingerprint { enrollment.lastGrant = previous?.lastGrant }
        enrollment.retiredCAFingerprints = previous?.retiredCAFingerprints
        if var rotation = previous?.caRotation ?? newRotation(step: .replacementAdded) {
            rotation.step = .replacementAdded
            enrollment.caRotation = rotation
        }
        func failed(_ text: String) -> (Bool, TemporaryAccessEnrollment, [String]) {
            enrollment.lastAuditResult = text
            return (false, enrollment, ["✗ " + text, "  Temporary access is not enabled for this server; fix the cause and run authorize again."])
        }

        let scope = CATrust.inspect(listing, caBlob: ca.publicKeyBlob, principal: principal)
        guard scope.isScoped else {
            return failed("\(scope.summary). Only a line with cert-authority, principals=\"\(principal)\" and the no-* "
                + "restrictions is accepted; fix or remove the line holding \(ca.fingerprint) in ~/.ssh/authorized_keys")
        }
        let hostKeys = HostKeys.known(for: resolved)
        guard !hostKeys.isEmpty else {
            return failed("no host key for this server in known_hosts, so its identity cannot be pinned. "
                + "Connect once with ssh so the key is recorded")
        }
        let outcome: CertificateLoginCheck.Outcome
        do {
            let validation = try makeValidation(ca: ca, principals: [principal], users: [resolved.user], lifetime: 600,
                                                paths: paths,
                                                purpose: "check that a server accepts temporary-access certificates (nothing is granted), requested by authorize")
            outcome = validation.check(hostname: resolved.hostname, user: resolved.user, port: resolved.port,
                                       principal: principal, hostKeys: hostKeys)
            validation.stop()
        } catch let error as SignError {
            return failed("the validation certificate was not signed: \(error.description)")
        } catch {
            return failed("could not sign a validation certificate: \(error)")
        }
        if case .failed(let reason) = outcome {
            return failed("the server did not accept a certificate from this CA (\(reason)). Check that its sshd allows "
                + "certificates (PubkeyAuthentication, PubkeyAcceptedAlgorithms) and reads ~/.ssh/authorized_keys")
        }
        var lines = ["✓ The server accepted a certificate from this Mac's CA for principal \(principal)."]
        if scope.otherAuthorities > 0 {
            lines.append("! \(scope.otherAuthorities) other cert-authority line(s) there are not managed by \(tool).")
        }
        enrollment.verified = true
        enrollment.lastAuditResult = "\(scope.summary); certificate login works"

        if !retiring.isEmpty {
            let fingerprints = retiring.map(\.fingerprint)
            let shown = fingerprints.joined(separator: ", ")
            enrollment.caRotation?.step = .retirementStarted
            let removal = try? RemoteKeys.runWithUserAccess(RemoteKeys.removeScript(retiring.compactMap(\.blob)), on: target)
            let remaining = RemoteKeys.listedLines(removal?.output ?? "")
            let after = CATrust.inspect(remaining, caBlob: ca.publicKeyBlob, principal: principal, retiredFingerprints: Set(fingerprints))
            guard removal?.ok == true, RemoteKeys.containsListing(removal?.output ?? ""), after.retiredLines == 0, after.isScoped else {
                enrollment.lastAuditResult = "certificate login works, but the previous CA \(shown) could not be removed"
                return (false, enrollment, lines + ["✗ The previous CA (\(shown)) could not be removed; run authorize again."])
            }
            enrollment.caRotation = nil
            enrollment.retiredCAFingerprints = Array(Set((enrollment.retiredCAFingerprints ?? []) + fingerprints)).sorted()
            lines.append("✓ Removed the previous CA (\(shown)) from authorized_keys. Other trust paths, "
                + "such as TrustedUserCAKeys in sshd_config, are not checked.")
        }
        return (true, enrollment, lines)
    }
}

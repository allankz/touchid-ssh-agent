import CryptoKit
import Darwin
import Foundation

/// The process behind one temporary grant (`touchid-ssh-agent access-job`),
/// normally a one-shot launchd job in the user's GUI session with restarts
/// disabled. It signs the frozen request with the CA (one Touch ID), publishes
/// the grant only after approval and only once the CLI confirms every target
/// works, serves signatures until the deadline or a stop, then removes
/// everything it created. A crash, logout or reboot ends the grant: nothing
/// restarts it and its private key existed only in this process.
public final class AccessJob {
    public typealias Signer = (_ data: Data, _ ca: StoredIdentity, _ reason: String, _ cancellation: SignCancellation) throws -> Data

    public struct Options {
        /// How long the job waits for the CLI to attach before giving up.
        public var attachTimeout: TimeInterval = 30
        /// How long it waits for the CLI's readiness verdict after issuance.
        public var confirmTimeout: TimeInterval = 180
        public var clock: GrantClock = SystemGrantClock()
        /// Period of the deadline check (it also catches a wake from sleep).
        public var checkInterval: TimeInterval = 2
        public var preventsIdleSleep = true
        public var observesWake = true

        public init() {}
    }

    public enum State: String {
        case starting
        case awaitingApproval = "awaiting-approval"
        case issued
        case active
        case ending
    }

    public static let defaultSigner: Signer = { data, ca, reason, cancellation in
        var timeout = SecureEnclaveSigner.defaultPromptTimeout
        if let value = ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_PROMPT_TIMEOUT"],
           let seconds = TimeInterval(value), seconds > 0 {
            timeout = seconds
        }
        return try SecureEnclaveSigner.sign(data, with: ca, reason: reason, timeout: timeout, cancellation: cancellation)
    }

    let paths: AgentPaths
    let directory: GrantDirectory
    let digest: String
    let signer: Signer
    let options: Options
    let log: EventLog

    private let lock = NSLock()
    private var state = State.starting
    private var owner: ControlConnection?
    private var ownerRequester = "unknown process"
    private var verdict: String?
    private var endReason: String?
    private let attached = DispatchSemaphore(value: 0)
    private let verdictReady = DispatchSemaphore(value: 0)
    private let finished = DispatchSemaphore(value: 0)
    private let cancellation = SignCancellation()
    private var controlSource: DispatchSourceRead?
    private var request: AccessRequest?
    private var deadline: GrantDeadline?
    private var credential: IssuedCertificate?
    private var agent: TemporaryAgent?
    private var assertion: IdleSleepAssertion?
    private var wake: WakeObserver?
    private var timer: DispatchSourceTimer?
    private var recordedGrant = false
    private var tornDown = false

    public init(paths: AgentPaths, grantDirectory: URL, digest: String,
                signer: @escaping Signer = AccessJob.defaultSigner, options: Options = Options()) {
        self.paths = paths
        let name = grantDirectory.lastPathComponent
        directory = GrantDirectory(paths: paths, grantId: name)
        self.digest = digest
        self.signer = signer
        self.options = options
        log = EventLog(url: paths.accessLogFile, echoToStderr: false)
        // Refuse a directory outside this data directory's grants folder.
        if directory.url.path != grantDirectory.standardizedFileURL.path { endReason = "invalid-directory" }
    }

    public var currentState: State { lock.lock(); defer { lock.unlock() }; return state }

    /// Ends the grant from any thread (stop request, signal, expiry, cancelled caller).
    public func requestEnd(_ reason: String) {
        lock.lock()
        if endReason == nil { endReason = reason }
        lock.unlock()
        cancellation.cancel()
        attached.signal()
        verdictReady.signal()
        finished.signal()
    }

    private var ending: String? { lock.lock(); defer { lock.unlock() }; return endReason }

    private func setState(_ newState: State) {
        lock.lock()
        state = newState
        lock.unlock()
    }

    /// Runs the whole grant and returns the process exit status.
    public func run() -> Int32 {
        guard ending == nil else {
            log.record("job-refused", ["reason": "invalid-directory"])
            return 2
        }
        let request: AccessRequest
        do {
            request = try loadRequest()
        } catch {
            // Not this job's directory (another request, or one a live job
            // serves): leave every file alone. The CLI cleans up its own.
            log.record("job-refused", ["grant": directory.grantId, "error": (error as? AccessError)?.code ?? "setup"])
            return 1
        }
        if let other = GrantManifest.read(from: directory)?.process, other.isRunning {
            log.record("job-refused", ["grant": directory.grantId, "error": "already-running"])
            return 1
        }
        do {
            try recordProcessIdentity()
            try startControl()
        } catch {
            log.record("job-failed", ["grant": directory.grantId, "error": (error as? AccessError)?.code ?? "setup"])
            return teardown(reason: "failed-start", status: 1)
        }
        self.request = request
        deadline = GrantDeadline(expiresAt: TimeInterval(request.validBefore), clock: options.clock)
        log.record("job-started", ["grant": request.grantId, "targets": String(request.targets.count)])

        // The CLI attaches first; without it nobody would receive the result.
        guard attached.wait(timeout: .now() + options.attachTimeout) == .success, ending == nil else {
            return teardown(reason: ending ?? "abandoned", status: 3)
        }

        setState(.awaitingApproval)
        do {
            let issued = try issue(request)
            credential = issued
            try publish(request, issued)
        } catch {
            let failure = failureDetails(error)
            owner?.send(["event": "failed", "code": failure.code, "message": failure.message])
            log.record("issuance-failed", ["grant": request.grantId, "why": failure.code])
            return teardown(reason: ending ?? failure.reason, status: 1)
        }

        setState(.issued)
        owner?.send([
            "event": "issued", "serial": NSNumber(value: credential?.certificate.serial ?? 0),
            "key_id": credential?.certificate.keyID ?? "",
            "temporary_key_fingerprint": credential?.fingerprint ?? "",
        ])
        // The CLI checks every target with the new certificate before the
        // grant is reported as usable; anything but a confirmation ends it.
        _ = verdictReady.wait(timeout: .now() + options.confirmTimeout)
        lock.lock()
        let confirmed = verdict == "confirm" && endReason == nil
        lock.unlock()
        guard confirmed else {
            return teardown(reason: ending ?? (verdict == nil ? "abandoned" : "readiness-failed"), status: 1)
        }
        guard deadline?.isExpired == false else { return teardown(reason: "expired", status: 0) }

        setState(.active)
        recordGrantStart(request)
        owner?.send(["event": "active"])
        log.record("active", ["grant": request.grantId, "serial": String(credential?.certificate.serial ?? 0),
                              "key_id": credential?.certificate.keyID ?? ""])
        finished.wait()
        return teardown(reason: ending ?? "stopped", status: 0)
    }

    // MARK: - Setup

    private func loadRequest() throws -> AccessRequest {
        var info = stat()
        guard AccessNames.isGrantId(directory.grantId), lstat(directory.url.path, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() else {
            throw AccessError.invalid(code: "invalid_request", message: "invalid grant directory")
        }
        guard let (data, request) = GrantStore.readRequest(directory), AccessRequest.digest(data) == digest else {
            throw AccessError.invalid(code: "invalid_request", message: "the request does not match the approved summary")
        }
        guard request.grantId == directory.grantId, request.dataDirectory == paths.directory.path else {
            throw AccessError.invalid(code: "invalid_request", message: "the request belongs to another grant")
        }
        try request.validate()
        return request
    }

    private func recordProcessIdentity() throws {
        guard let data = GrantStore.readSmallFile(directory.manifest),
              var manifest = try? JSON.decoder.decode(GrantManifest.self, from: data),
              manifest.grantId == directory.grantId, let identity = ProcessIdentity.current() else {
            throw AccessError.invalid(code: "invalid_request", message: "missing grant manifest")
        }
        manifest.process = identity
        try manifest.write(to: directory)
    }

    private func startControl() throws {
        let fd = try UnixSocket.listen(at: directory.controlSocket.path, backlog: 8)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "touchid-ssh-agent.access.control"))
        source.setEventHandler { [weak self] in
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            guard let self else { close(client); return }
            let thread = Thread { self.serveControl(ControlConnection(fd: client)) }
            thread.start()
        }
        source.setCancelHandler { close(fd) }
        controlSource = source
        source.resume()
    }

    private func serveControl(_ connection: ControlConnection) {
        guard let peer = PeerInspector.credentials(of: connection.fd), peer.uid == getuid() else {
            connection.close()
            return
        }
        guard let message = connection.receive(timeout: 10), let op = message["op"] as? String else {
            connection.close()
            return
        }
        switch op {
        case "attach":
            lock.lock()
            let accepted = owner == nil && endReason == nil
            if accepted {
                owner = connection
                ownerRequester = PeerInspector.describe(peer.pid.map { PeerInspector.processChain(from: $0) } ?? [])
            }
            lock.unlock()
            guard accepted else {
                connection.send(["event": "failed", "code": "access_busy", "message": "another command already follows this grant"])
                connection.close()
                return
            }
            connection.send(["event": "attached", "grant_id": directory.grantId])
            attached.signal()
            followOwner(connection)
        case "status":
            connection.send(statusMessage())
            connection.close()
        case "stop":
            connection.send(["event": "stopping", "grant_id": directory.grantId])
            connection.close()
            log.record("stop-requested", ["grant": directory.grantId])
            requestEnd("stopped")
        default:
            connection.send(["event": "failed", "code": "invalid_request", "message": "unknown control operation"])
            connection.close()
        }
    }

    /// Reads the attached CLI's verdict. If it goes away before confirming
    /// (interrupted, killed), the grant is withdrawn, even mid-prompt.
    private func followOwner(_ connection: ControlConnection) {
        while true {
            guard let message = connection.receive() else {
                if currentState != .active {
                    log.record("caller-gone", ["grant": directory.grantId])
                    requestEnd("cancelled")
                }
                return
            }
            switch message["op"] as? String {
            case "confirm":
                lock.lock()
                verdict = "confirm"
                lock.unlock()
                verdictReady.signal()
            case "abort":
                lock.lock()
                verdict = "abort"
                lock.unlock()
                requestEnd((message["reason"] as? String) == "readiness-failed" ? "readiness-failed" : "cancelled")
            case "status":
                connection.send(statusMessage())
            default:
                break
            }
        }
    }

    private func statusMessage() -> [String: Any] {
        var message: [String: Any] = ["event": "status", "grant_id": directory.grantId, "state": currentState.rawValue]
        if let request { message["expires_at"] = NSNumber(value: request.validBefore) }
        if let deadline { message["remaining_seconds"] = NSNumber(value: Int(deadline.remaining)) }
        if let credential {
            message["serial"] = NSNumber(value: credential.certificate.serial)
            message["temporary_key_fingerprint"] = credential.fingerprint
        }
        return message
    }

    // MARK: - Issuance

    /// The Touch ID dialog reads "“touchid-ssh-agent” is trying to <reason>."
    public static func promptReason(_ request: AccessRequest, requester: String) -> String {
        let count = request.targets.count
        let command = request.permissions.forceCommand == nil ? "" : " (one fixed command)"
        return "allow temporary SSH access to \(count) target\(count == 1 ? "" : "s") for "
            + "\(AccessDuration.describe(request.duration))\(command), requested by \(DisplayText.sanitize(requester, maxLength: 60))"
    }

    private func issue(_ request: AccessRequest) throws -> IssuedCertificate {
        guard let ca = try CertificateAuthorityStore.load(from: paths) else {
            throw AccessError.invalid(code: "ca_missing", message: "this Mac has no temporary-access CA. Run `touchid-ssh-agent authorize HOST --temporary-access`.")
        }
        guard ca.fingerprint == request.caFingerprint else {
            throw AccessError.invalid(code: "ca_mismatch", message: "the CA changed after the request was validated")
        }
        guard let deadline, !deadline.isExpired else {
            throw AccessError.invalid(code: "access_expired", message: "the requested deadline passed before approval")
        }
        let serial = try CertificateSerial.next(paths: paths)
        let keyID = CertificateIssuer.keyID(prefix: "access", at: Date(timeIntervalSince1970: TimeInterval(request.requestedAt)), serial: serial)
        lock.lock()
        let requester = ownerRequester
        lock.unlock()
        let reason = AccessJob.promptReason(request, requester: requester)
        owner?.send(["event": "approval-requested", "serial": NSNumber(value: serial)])
        log.record("approval-requested", ["grant": request.grantId, "serial": String(serial), "key_id": keyID, "requester": requester])
        let issued = try CertificateIssuer.issue(
            ca: ca.publicKeyBlob, serial: serial, keyID: keyID, principals: request.principals,
            validAfter: request.validAfter, validBefore: request.validBefore,
            criticalOptions: request.permissions.criticalOptions, extensions: request.permissions.extensions
        ) { toBeSigned in
            try signer(toBeSigned, ca, reason, cancellation)
        }
        log.record("issued", ["grant": request.grantId, "serial": String(serial), "key_id": keyID])
        return issued
    }

    private func publish(_ request: AccessRequest, _ issued: IssuedCertificate) throws {
        guard ending == nil else { throw AccessError.invalid(code: "cancelled", message: "the request was cancelled") }
        let comment = "touchid-ssh-agent-access-\(request.grantId)"
        try SecureFile.writeAtomically(Data((Ed25519SSH.publicKeyLine(issued.publicKeyBlob, comment: comment) + "\n").utf8),
                                       to: directory.publicKey, mode: 0o600)
        try SecureFile.writeAtomically(Data((SSHCertificate.publicKeyLine(blob: issued.blob, comment: comment) + "\n").utf8),
                                       to: directory.certificate, mode: 0o600)
        try SecureFile.writeAtomically(Data(GrantSSHConfig.knownHosts(request).utf8), to: directory.knownHosts, mode: 0o600)
        try SecureFile.writeAtomically(Data(try GrantSSHConfig.render(request, in: directory).utf8), to: directory.sshConfig, mode: 0o600)
        guard let deadline else { throw AccessError.invalid(code: "internal_error", message: "no deadline") }
        let agent = TemporaryAgent(socketPath: directory.agentSocket.path, credential: issued, deadline: deadline,
                                   allowedUsers: Set(request.targets.map(\.user)), comment: comment,
                                   log: log, logName: request.grantId)
        try agent.start()
        self.agent = agent
        if options.preventsIdleSleep { assertion = IdleSleepAssertion(reason: "touchid-ssh-agent temporary SSH access") }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "touchid-ssh-agent.access.deadline"))
        timer.schedule(wallDeadline: .now() + options.checkInterval, repeating: options.checkInterval, leeway: .milliseconds(500))
        timer.setEventHandler { [weak self] in self?.checkDeadline() }
        self.timer = timer
        timer.resume()
        if options.observesWake { wake = WakeObserver { [weak self] in self?.checkDeadline() } }
    }

    private func checkDeadline() {
        if deadline?.isExpired == true { requestEnd("expired") }
    }

    private func failureDetails(_ error: Error) -> (code: String, message: String, reason: String) {
        if let reason = ending {
            return reason == "stopped"
                ? ("stopped", "the request was stopped before it was approved", reason)
                : ("cancelled", "the request was cancelled before it was approved", reason)
        }
        switch error {
        case let error as AccessError:
            return (error.code, error.description, "failed-start")
        case SignError.canceled, SignError.authenticationFailed:
            return ("approval_denied", "Touch ID approval was denied; no grant was issued.", "denied")
        case SignError.timedOut:
            return ("approval_timeout", "Nobody approved Touch ID in time; no grant was issued.", "timeout")
        case let error as SignError where error == .biometryLockout || error == .biometryUnavailable
            || error == .biometryNotEnrolled || error == .deviceLocked:
            return ("approval_unavailable", "Touch ID could not ask for approval: \(error.description)", "unavailable")
        case let error as SignError:
            return ("ca_unusable", """
            The CA could not sign: \(error.description). Adding or removing a fingerprint invalidates it. \
            To replace it, move ca.se and ca.pub out of \(paths.displayPath(paths.directory)), then run \
            `touchid-ssh-agent authorize HOST --temporary-access` for each enrolled server.
            """, "failed-start")
        default:
            return ("internal_error", "\(error)", "failed-start")
        }
    }

    // MARK: - Inventory

    private func recordGrantStart(_ request: AccessRequest) {
        guard let credential else { return }
        let issuedAt = Date.wholeSecondsNow
        do {
            try InventoryStore.update(paths) { inventory in
                for index in inventory.servers.indices {
                    guard let enrollment = inventory.servers[index].temporaryAccess,
                          let target = request.targets.first(where: { $0.targetId == enrollment.targetId }) else { continue }
                    inventory.servers[index].temporaryAccess?.lastGrant = GrantSummary(
                        grantId: request.grantId, serial: credential.certificate.serial,
                        temporaryKeyFingerprint: credential.fingerprint, sshAlias: target.sshAlias, issuedAt: issuedAt,
                        expiresAt: request.expiresAt, forceCommand: request.permissions.forceCommand, pty: request.permissions.pty)
                }
            }
            recordedGrant = true
        } catch {
            log.record("inventory-error", ["grant": request.grantId])
        }
    }

    private func recordGrantEnd(_ reason: String) {
        guard recordedGrant, let request else { return }
        try? InventoryStore.update(paths) { inventory in
            for index in inventory.servers.indices
            where inventory.servers[index].temporaryAccess?.lastGrant?.grantId == request.grantId {
                inventory.servers[index].temporaryAccess?.lastGrant?.endedAt = .wholeSecondsNow
                inventory.servers[index].temporaryAccess?.lastGrant?.endReason = reason
            }
        }
    }

    // MARK: - Teardown

    /// Stops signing, closes clients, removes every file the grant created and
    /// releases the sleep assertion. Authenticated SSH sessions keep running.
    private func teardown(reason: String, status: Int32) -> Int32 {
        lock.lock()
        let first = !tornDown
        tornDown = true
        state = .ending
        lock.unlock()
        guard first else { return status }
        cancellation.cancel()
        timer?.cancel()
        wake?.stop()
        agent?.stop()
        controlSource?.cancel()
        controlSource = nil
        unlink(directory.controlSocket.path)
        owner?.close()
        GrantStore.removeOwnedFiles(grantId: directory.grantId, paths: paths)
        assertion?.release()
        recordGrantEnd(reason)
        log.record("ended", ["grant": directory.grantId, "reason": reason])
        return status
    }
}

extension Ed25519SSH {
    public static func publicKeyLine(_ blob: Data, comment: String) -> String {
        SSHKeyFormat.authorizedKeyLine(blob: blob, comment: comment)
    }
}

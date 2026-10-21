import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import TouchIDSSHCore

let version = "0.2.1-dev"
let tool = "touchid-ssh-agent"

/// The help text, grouped by what the user is doing.
var usage: String {
    func section(_ title: String, _ lines: String) -> String { Out.bold(title) + "\n" + lines }
    return [
        "\(tool) \(version) — SSH agent with a Secure Enclave key and Touch ID for every signature",
        "Usage: \(tool) COMMAND [OPTIONS]\nAI agents: run `\(tool) instructions` first. It explains how to use this tool.",
        section("Getting started", """
          setup [--biometry current-set|any] [--comment TEXT]
                            Guided setup: Touch ID key, backup folder and emergency kit.
          install [--force] Starts the agent with your session (LaunchAgent).
          authorize [user@]host [-p PORT] [-F SSH_CONFIG] [--alias NAME] [--temporary-access] [-- SSH_ARGS]
                            Installs both keys on a server, checks the Touch ID login,
                            offers a ~/.ssh/config block and updates the inventory.
                            --temporary-access also trusts this Mac's CA there, once,
                            so `access` can grant temporary logins to it.
        """),
        section("Day to day", """
          status            Secure Enclave, Touch ID, keys, agent, backup, inventory and
                            temporary access.
          inventory         Lists the servers in the inventory.
          audit [NAME...]   Checks that every server still has both keys and, where enrolled,
                            the CA's scope (one Touch ID each).
          deauthorize NAME... | --all [-F SSH_CONFIG] [-p PORT] [-- SSH_ARGS]
                            Removes this Mac's keys from servers and drops them from the
                            inventory. --all does every server, then offers to delete
                            this Mac's Touch ID key.
          config NAME --host HOST [--user USER] [--port PORT]
                            Prints a ~/.ssh/config block. Changes no file.
          set backup-path DIR|none
                            Folder, ideally synced to the cloud, for the encrypted inventory.
        """),
        section("Temporary access", """
          access HOST[,HOST...] --for DURATION [--force-command COMMAND] [--allow-pty] [--json]
                            Requests a temporary grant; one Touch ID approves issuance.
          access status [--json]
                            Shows validity, selected targets, aliases and exact SSH commands.
          access stop [--json]
                            Stops the active grant and removes its local generated files.
          access cleanup [--json]
                            Removes stale generated files; keeps live, valid grants.
          access help       Enrollment, inventory, aliases, cleanup and limits in detail.
          instructions [--snippet | --add-to FILE]
                            Prints the workflow for AI agents. --snippet prints a short block
                            for CLAUDE.md or AGENTS.md; --add-to writes it there after asking.
        """),
        section("New Mac and recovery", """
          migrate           Shows, with this Mac's data, how to move to a new Mac.
          recovery test KIT [--inventory FILE] [-F SSH_CONFIG]
                            Checks that the emergency kit still opens every server.
                            Changes nothing.
          recover KIT [--inventory FILE] [-F SSH_CONFIG] [--keep-emergency-key]
                            On a new Mac: moves every server to this Mac, then audits.
          recovery create [--replace] [--own-passphrase]
                            Creates a new emergency kit (kept off this Mac).
          recovery import FILE.pub [--replace]
                            Uses an emergency key you already have; only its public key
                            is copied.
          recovery pubkey   Prints the emergency public key.
        """),
        section("Advanced", """
          create [--comment TEXT] [--biometry current-set|any]
                            Creates only the Touch ID key. Default: current-set (adding or
                            removing a fingerprint invalidates the key; the emergency key
                            covers that).
          pubkey            Prints the Touch ID public key (authorized_keys line).
          fingerprint       Prints its SHA256 fingerprint.
          agent             Runs the agent in the foreground.
          uninstall         Removes the LaunchAgent. The keys are kept.
          version           Prints the version.
        """),
        """
        Directory: \(AgentPaths.defaultDirectory.path) (or $\(AgentPaths.environmentVariable)).
        Time to approve Touch ID: 60 s (or $TOUCHID_SSH_AGENT_PROMPT_TIMEOUT).
        For AI agents: `\(tool) instructions` prints how to use temporary SSH access.
        To make your agent read it, add a pointer to its instructions file once:
            \(tool) instructions --add-to ~/.claude/CLAUDE.md   (Claude Code)
            \(tool) instructions --add-to ~/.codex/AGENTS.md    (Codex)
        """,
    ].joined(separator: "\n\n")
}

struct UsageError: Error, CustomStringConvertible {
    let description: String
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    fflush(stdout)
    let margin = isatty(STDERR_FILENO) == 1 ? Out.margin : ""
    let text = message.split(separator: "\n", omittingEmptySubsequences: false)
        .enumerated().map { $0.offset == 0 ? "\(margin)error: \($0.element)" : "\(margin)\($0.element)" }
        .joined(separator: "\n")
    FileHandle.standardError.write(Data((text + "\n").utf8))
    exit(code)
}

/// Parses `--name value` options; flags listed in `booleans` take no value.
func parseOptions(_ arguments: ArraySlice<String>, booleans: Set<String> = []) throws -> (positional: [String], options: [String: String]) {
    var positional: [String] = []
    var options: [String: String] = [:]
    var iterator = arguments.makeIterator()
    while let argument = iterator.next() {
        if argument.hasPrefix("--") {
            let name = String(argument.dropFirst(2))
            if booleans.contains(name) {
                options[name] = "true"
            } else if let value = iterator.next() {
                options[name] = value
            } else {
                throw UsageError(description: "option --\(name) needs a value")
            }
        } else {
            positional.append(argument)
        }
    }
    return (positional, options)
}

func requireIdentity(_ paths: AgentPaths) -> StoredIdentity {
    do {
        guard let identity = try IdentityStore.load(from: paths) else {
            fail("no identity in \(paths.displayPath(paths.directory)). Run `\(tool) create`.")
        }
        return identity
    } catch {
        fail("\(error)")
    }
}

func sshConfigBlock(alias: String, host: String, user: String?, port: String?, paths: AgentPaths) -> String {
    var lines = ["Host \(alias)", "  HostName \(host)"]
    if let user { lines.append("  User \(user)") }
    if let port { lines.append("  Port \(port)") }
    lines += [
        "  IdentityAgent \(paths.displayPath(paths.socket))",
        "  IdentityFile \(paths.displayPath(paths.publicKeyFile))",
        "  IdentitiesOnly yes",
        "  ForwardAgent no",
    ]
    return lines.joined(separator: "\n")
}

// MARK: - Commands

func create(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let (_, options) = try parseOptions(arguments)
    let policyName = options["biometry"] ?? BiometryPolicy.currentSet.rawValue
    guard let policy = BiometryPolicy(rawValue: policyName) else {
        throw UsageError(description: "--biometry must be current-set or any")
    }
    let identity = try IdentityStore.create(
        in: paths,
        policy: policy,
        comment: options["comment"] ?? IdentityStore.defaultComment()
    )
    Out.say("""
    Identity created in the Secure Enclave (policy: \(policy.rawValue)).

    Fingerprint: \(identity.fingerprint)
    Public key (\(paths.displayPath(paths.publicKeyFile))):

    \(identity.authorizedKeyLine)

    Next steps:
      1. Create the emergency kit and backup folder:  \(tool) setup
      2. Start the agent:  \(tool) install
      3. Install both keys on each server:  \(tool) authorize user@server -p PORT
      4. Generate the ~/.ssh/config block:  \(tool) config my-server --host server --user user
    """)
}

func pubkey(paths: AgentPaths) {
    print(requireIdentity(paths).authorizedKeyLine)
}

func fingerprint(paths: AgentPaths) {
    print(requireIdentity(paths).fingerprint)
}

func biometryStatus() -> String {
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        return "available"
    }
    switch error.flatMap({ LAError.Code(rawValue: $0.code) }) {
    case .biometryLockout?:
        return "LOCKED OUT — lock the screen (⌃⌘Q) and unlock it with your password"
    case .biometryNotEnrolled?:
        return "no fingerprints enrolled"
    default:
        return "unavailable (\(error?.localizedDescription ?? "no details"))"
    }
}

func status(paths: AgentPaths) {
    Out.say("Secure Enclave: \(SecureEnclave.isAvailable ? "available" : "unavailable")")
    Out.say("Touch ID:       \(biometryStatus())")

    var identity: StoredIdentity?
    do {
        identity = try IdentityStore.load(from: paths)
        if let identity {
            Out.say("Identity:       \(identity.fingerprint) (\(identity.comment))")
        } else {
            Out.say("Identity:       none — run `\(tool) setup`")
        }
    } catch {
        Out.say("Identity:       error — \(error)")
    }

    let socket = paths.displayPath(paths.socket)
    if let offered = AgentClient.listIdentities(socketPath: paths.socket.path) {
        let offersIdentity = identity.map { id in offered.contains { $0.blob == id.publicKeyBlob } } ?? false
        Out.say("Agent:          running at \(socket)\(offersIdentity ? " (offering the identity)" : " (no identity)")")
    } else {
        Out.say("Agent:          stopped (\(socket))")
    }

    if LaunchAgent.isLoaded {
        Out.say("LaunchAgent:    loaded (\(LaunchAgent.label))")
    } else if FileManager.default.fileExists(atPath: LaunchAgent.plistURL.path) {
        Out.say("LaunchAgent:    installed but not loaded")
    } else {
        Out.say("LaunchAgent:    not installed — run `\(tool) install`")
    }
    recoveryStatus(paths: paths)
}

func config(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let (positional, options) = try parseOptions(arguments)
    guard positional.count == 1, let host = options["host"] else {
        throw UsageError(description: "usage: \(tool) config ALIAS --host HOST [--user USER] [--port PORT]")
    }
    print(sshConfigBlock(alias: positional[0], host: host, user: options["user"], port: options["port"], paths: paths))
}

func runAgent(paths: AgentPaths) throws -> Never {
    let log = EventLog(url: paths.logFile, echoToStderr: isatty(STDERR_FILENO) == 1)
    var timeout = SecureEnclaveSigner.defaultPromptTimeout
    if let value = ProcessInfo.processInfo.environment["TOUCHID_SSH_AGENT_PROMPT_TIMEOUT"] {
        guard let seconds = TimeInterval(value), seconds > 0 else {
            throw UsageError(description: "TOUCHID_SSH_AGENT_PROMPT_TIMEOUT must be a number of seconds")
        }
        timeout = seconds
    }
    let server = AgentServer(paths: paths, log: log) { data, identity, reason in
        try SecureEnclaveSigner.sign(data, with: identity, reason: reason, timeout: timeout)
    }
    do {
        try server.start()
    } catch AgentServerError.alreadyRunning(let path) {
        // Exit 0 so launchd (KeepAlive SuccessfulExit=false) does not loop.
        print("Another agent is already serving \(path); nothing to do.")
        exit(0)
    }

    var sources: [DispatchSourceSignal] = []
    for signalNumber in [SIGINT, SIGTERM, SIGHUP] {
        signal(signalNumber, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
        source.setEventHandler {
            server.stop()
            log.record("stopped")
            exit(0)
        }
        source.resume()
        sources.append(source)
    }
    withExtendedLifetime(sources) { dispatchMain() }
}

func install(_ arguments: ArraySlice<String>, paths: AgentPaths) throws {
    let (_, options) = try parseOptions(arguments, booleans: ["force"])
    guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath().path else {
        throw UsageError(description: "could not determine the path of this executable")
    }
    if executable.contains("/.build/"), options["force"] == nil {
        throw UsageError(description: """
        this binary lives in .build/ and would vanish after `swift package clean`.
        Install it with `make install` and run \(tool) install from there (or use --force).
        """)
    }
    try LaunchAgent.install(executable: executable, paths: paths)

    var listening = false
    for _ in 0..<20 where !listening {
        usleep(100_000)
        listening = AgentClient.isListening(socketPath: paths.socket.path)
    }
    Out.say("LaunchAgent \(LaunchAgent.label) installed: \(LaunchAgent.plistURL.path)")
    Out.say(listening
        ? "Agent running at \(paths.displayPath(paths.socket))."
        : "Warning: the agent has not answered yet; see \(paths.displayPath(paths.directory))/agent.stderr.log")
}

func uninstall() throws {
    try LaunchAgent.uninstall()
    Out.say("LaunchAgent removed. The keys stay on this Mac; `\(tool) deauthorize --all` takes them off your servers.")
}


func runAccessJob(directory: String, digest: String, paths: AgentPaths) -> Never {
    signal(SIGPIPE, SIG_IGN)
    let job = AccessJob(paths: paths, grantDirectory: URL(fileURLWithPath: directory), digest: digest)
    var sources: [DispatchSourceSignal] = []
    // launchd bootout and logout send SIGTERM: end the grant and clean up.
    for signalNumber in [SIGINT, SIGTERM, SIGHUP] {
        signal(signalNumber, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: DispatchQueue.global())
        source.setEventHandler { job.requestEnd("stopped") }
        source.resume()
        sources.append(source)
    }
    let status = withExtendedLifetime(sources) { job.run() }
    exit(status)
}

// MARK: - Entry point

let arguments = CommandLine.arguments.dropFirst()
let paths = AgentPaths.fromEnvironment()
let rest = arguments.dropFirst()

/// Output meant for files and scripts stays bare; everything else gets spacing.
let machineReadable: Set<String> = ["pubkey", "fingerprint", "config", "agent", "version", "--version",
                                    "access", "access-job", "instructions"]
if !machineReadable.contains(arguments.first ?? "help"), !(arguments.first == "recovery" && rest.first == "pubkey") {
    print("")
    atexit { print("") }
}

do {
    switch arguments.first {
    case "setup": try setup(rest, paths: paths)
    case "authorize": try authorize(rest, paths: paths)
    case "audit": try audit(rest, paths: paths)
    case "recover": try recover(rest, paths: paths, dryRun: false)
    case "inventory": try listInventory(paths: paths)
    case "recovery": try recovery(rest, paths: paths)
    case "set":
        guard rest.first == "backup-path", rest.count == 2 else {
            throw UsageError(description: "usage: \(tool) set backup-path DIR|none")
        }
        try setBackupFolder(rest[rest.startIndex + 1], paths: paths)
    case "create": try create(rest, paths: paths)
    case "pubkey": pubkey(paths: paths)
    case "fingerprint": fingerprint(paths: paths)
    case "status": status(paths: paths)
    case "config": try config(rest, paths: paths)
    case "agent": try runAgent(paths: paths)
    case "install": try install(rest, paths: paths)
    case "uninstall": try uninstall()
    case "deauthorize": try deauthorize(rest, paths: paths)
    case "migrate": try migrate(paths: paths)
    case "access": access(rest, paths: paths)
    case "instructions": try instructions(rest)
    case "access-job":
        // Internal: the process behind one grant, started by `access`.
        guard rest.count == 2 else { throw UsageError(description: "access-job is started by `\(tool) access`") }
        runAccessJob(directory: rest[rest.startIndex], digest: rest[rest.startIndex + 1], paths: paths)
    case "delete":
        // Replaced by deauthorize --all; kept so the old name explains where it went.
        throw UsageError(description: """
        `delete` was replaced by `\(tool) deauthorize --all`, which first removes this
        Mac's keys from your servers and then offers to delete the Touch ID key.
        """)
    case "version", "--version": print(version)
    case nil, "help", "--help", "-h": Out.say(usage)
    case let command?: throw UsageError(description: "unknown command: \(command)\n\n\(usage)")
    }
} catch {
    fail("\(error)")
}

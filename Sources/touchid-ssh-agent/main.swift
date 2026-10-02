import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import TouchIDSSHCore

let version = "0.1.0"
let tool = "touchid-ssh-agent"

let usage = """
\(tool) \(version) — SSH agent with a Secure Enclave key and Touch ID for every signature

Usage:
  \(tool) setup [--biometry current-set|any] [--comment TEXT]
        Guided setup: Touch ID key, backup folder and emergency kit.
  \(tool) authorize [user@]host [-p PORT] [-F SSH_CONFIG] [--alias NAME] [-- SSH_ARGS]
        Installs the Touch ID key and the emergency key on a server, checks
        the Touch ID login and updates the inventory and its backup.
  \(tool) audit [ALIAS...]  Checks that every server in the inventory has both keys.
  \(tool) inventory       Lists the servers in the inventory.
  \(tool) set backup-path DIR|none
        Folder (ideally synced to the cloud) for the encrypted inventory.
  \(tool) recovery create [--replace] [--own-passphrase]
        Creates a new emergency kit (passphrase-protected key, kept off this Mac).
  \(tool) recovery import FILE.pub [--replace]
        Uses an emergency key you already have; only its public key is copied.
  \(tool) recovery pubkey Prints the emergency public key.
  \(tool) create [--comment TEXT] [--biometry current-set|any]
        Creates only the Touch ID key. Default: current-set (adding or removing
        a fingerprint invalidates the key; the emergency key covers that).
  \(tool) pubkey          Prints the public key (authorized_keys line).
  \(tool) fingerprint     Prints the SHA256 fingerprint of the public key.
  \(tool) status          Diagnostics: Secure Enclave, Touch ID, identity and agent.
  \(tool) config ALIAS --host HOST [--user USER] [--port PORT]
        Prints a ~/.ssh/config block. Does not change any file.
  \(tool) agent           Runs the agent in the foreground.
  \(tool) install [--force]
        Registers the agent as a LaunchAgent (starts with your session).
  \(tool) uninstall       Removes the LaunchAgent. The identity is kept.
  \(tool) delete          Deletes the identity irreversibly.

Directory: \(AgentPaths.defaultDirectory.path) (or $\(AgentPaths.environmentVariable)).
Time to approve Touch ID: 60 s (or $TOUCHID_SSH_AGENT_PROMPT_TIMEOUT).
"""

struct UsageError: Error, CustomStringConvertible {
    let description: String
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
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
    print("""
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
    print("Secure Enclave: \(SecureEnclave.isAvailable ? "available" : "unavailable")")
    print("Touch ID:       \(biometryStatus())")

    var identity: StoredIdentity?
    do {
        identity = try IdentityStore.load(from: paths)
        if let identity {
            print("Identity:       \(identity.fingerprint) (\(identity.comment))")
        } else {
            print("Identity:       none — run `\(tool) setup`")
        }
    } catch {
        print("Identity:       error — \(error)")
    }

    let socket = paths.displayPath(paths.socket)
    if let offered = AgentClient.listIdentities(socketPath: paths.socket.path) {
        let offersIdentity = identity.map { id in offered.contains { $0.blob == id.publicKeyBlob } } ?? false
        print("Agent:          running at \(socket)\(offersIdentity ? " (offering the identity)" : " (no identity)")")
    } else {
        print("Agent:          stopped (\(socket))")
    }

    if LaunchAgent.isLoaded {
        print("LaunchAgent:    loaded (\(LaunchAgent.label))")
    } else if FileManager.default.fileExists(atPath: LaunchAgent.plistURL.path) {
        print("LaunchAgent:    installed but not loaded")
    } else {
        print("LaunchAgent:    not installed — run `\(tool) install`")
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
    print("LaunchAgent \(LaunchAgent.label) installed: \(LaunchAgent.plistURL.path)")
    print(listening
        ? "Agent running at \(paths.displayPath(paths.socket))."
        : "Warning: the agent has not answered yet; see \(paths.displayPath(paths.directory))/agent.stderr.log")
}

func uninstall() throws {
    try LaunchAgent.uninstall()
    print("LaunchAgent removed. The identity stays on disk; use `\(tool) delete` to delete it.")
}

func delete(paths: AgentPaths) throws {
    let identity = requireIdentity(paths)
    print("""
    This permanently deletes the identity \(identity.fingerprint) (\(identity.comment)).
    Servers that only accept this key will stop accepting your login.
    Type DELETE to confirm:
    """, terminator: " ")
    guard readLine(strippingNewline: true) == "DELETE" else {
        print("Nothing was deleted.")
        return
    }
    try IdentityStore.delete(from: paths)
    print("Identity deleted.")
}

// MARK: - Entry point

let arguments = CommandLine.arguments.dropFirst()
let paths = AgentPaths.fromEnvironment()
let rest = arguments.dropFirst()

do {
    switch arguments.first {
    case "setup": try setup(rest, paths: paths)
    case "authorize": try authorize(rest, paths: paths)
    case "audit": try audit(rest, paths: paths)
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
    case "delete": try delete(paths: paths)
    case "version", "--version": print(version)
    case nil, "help", "--help", "-h": print(usage)
    case let command?: throw UsageError(description: "unknown command: \(command)\n\n\(usage)")
    }
} catch {
    fail("\(error)")
}

# Contributing to touchid-ssh-agent

Thanks for your interest in improving touchid-ssh-agent. The project is small and experimental, and it guards SSH access, so changes are reviewed with security first and features second.

- **Security problems**: do not open a public issue. Follow [`SECURITY.md`](SECURITY.md).
- **Bugs and ideas**: open an issue. For anything larger than a small fix, describe the change in an issue before writing code, so we can agree on the approach.

## Ground rules

These are the project's promises to its users. Changes that weaken any of them need an issue and an explicit discussion first.

- **The private key never leaves the Secure Enclave.** No export, no backup, no copy in memory or on disk.
- **Every signature needs Touch ID.** No reuse window, no silent mode, no "remember for N minutes", no password fallback.
- **Small protocol surface.** The agent answers only "list identities" and "sign"; everything else gets `SSH_AGENT_FAILURE`.
- **The emergency kit stays off the Mac.** Only its public key is stored locally; the inventory backup is encrypted to it.
- **No network calls, accounts or telemetry** from the agent. `authorize` and `audit` only talk to the servers the user names, through `ssh`.
- **Logs carry no secrets**: no key material, payloads, remote user names or hosts.
- **No new dependencies** without discussion. The package has no Swift dependencies; `age` is the only external tool besides what ships with macOS.

## Requirements

- A Mac with Touch ID (Apple Silicon or T2), macOS 13 or later.
- Swift 5.10 or later. The Command Line Tools are enough (`xcode-select --install`); Xcode is not required.
- [age](https://age-encryption.org): `brew install age`.
- Docker, for the end-to-end tests against a real `sshd`.
- `expect`, which ships with macOS, for the interactive flows.

## Build and test

```bash
make build          # release build of the CLI
make test           # wire format, protocol, Secure Enclave, agent, emergency kit, CLI flows
make test-docker    # adds real SSH logins, authorize and audit against an sshd container
make test-touchid   # interactive: approve, deny and time out real Touch ID prompts
```

- XCTest does not ship with the Command Line Tools, so the suite is a plain executable in `Tests/SelfTest/` that uses OpenSSH (`ssh-keygen`, `ssh-add`, `ssh`) and `age` as oracles.
- Keep the Mac **unlocked** while tests run: the Secure Enclave refuses operations while the screen is locked.
- Tests create Secure Enclave keys **without** Touch ID through the `@_spi(Testing)` API, and only in temporary directories. Never point tests at `~/.touchid-ssh-agent`.
- Run `make test-touchid` whenever you touch signing, the Touch ID prompt, the agent server or the LaunchAgent. No automated test can press the sensor.

## Project layout

- `Sources/TouchIDSSHCore/`: SSH wire format, agent protocol, identity, signer, server, LaunchAgent, emergency kit, inventory and remote key management.
- `Sources/touchid-ssh-agent/`: the CLI.
- `Tests/SelfTest/`: the test suite.
- `Tests/e2e/`: the `sshd` image used by the Docker tests.
- `scripts/`: the interactive Touch ID test.
- `docs/`: design notes for each phase.

## Making a change

1. **Write the test first, or alongside the code.**
   - Parsing and encoding: test with vectors and with OpenSSH as the oracle.
   - Anything that talks to a server: test against the Docker `sshd`.
   - Anything interactive: drive it through `expect`.
2. **Match the surrounding code**: Swift 5 language mode, the same naming and comment density. Comments explain *why*, not *what*.
3. **Write user-facing text in English** (CLI output, errors, docs), and make errors actionable: say what to run next.
4. **Never handle passphrases through command-line arguments or environment variables.** Other processes can read both. Use stdin, as the emergency kit builder does.
5. **Treat everything from the socket or the server as untrusted.** Bound every read, and sanitize anything shown in the Touch ID prompt or written to the log.
6. **Update the docs** (README, SECURITY.md, `docs/`) when behavior changes.

## No real infrastructure in the repository

Do not commit real host names, IP addresses, user names, ports or keys, not even in tests or examples. Use `server.example`, `example.invalid`, `203.0.113.0/24` and generated test keys. If you can, scan your changes before pushing:

```bash
docker run --rm -v "$PWD:/repo:ro" zricethezav/gitleaks:latest git /repo
```

## Commits and pull requests

- Keep commits small and focused. Use an imperative subject in English ("Add audit command", not "Added…"), and use the body to explain *why*.
- In the pull request, describe what changed, why, and how you tested it: which `make` targets you ran, and whether you ran `make test-touchid`.
- `make test` must pass. Run `make test-docker` too when you touch `authorize`, `audit`, the agent or the protocol.

## Reporting a bug

Please include:

- macOS version and Mac model;
- the output of `touchid-ssh-agent status`, with anything private redacted;
- what you ran, what you expected, and what happened;
- relevant lines from `~/.touchid-ssh-agent/agent.log`, which never contains keys or payloads.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE) that covers the project.

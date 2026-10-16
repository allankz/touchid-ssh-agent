# Implementation prompt: Phase 2 temporary SSH access

> **Historical handoff.** This is the brief Phase 2 was built from; it shipped in version 0.2.0. Its "remains version 0.1.0" and "not implemented" statements describe the starting point. For what was built and validated, see [`docs/phase-2-implementation.md`](docs/phase-2-implementation.md).

Implement Phase 2 of `touchid-ssh-agent` in this repository. Deliver the production feature, recovery integration, tests and accurate documentation described below. The user approved this direction in the planning discussion; continue implementation without another design approval or requiring a new issue. Complete the work within this scope and report evidence for each acceptance gate.

All paths below are relative to the repository root. This document is the implementation handoff. The checkpoint containing it includes design documents and a disposable feasibility probe; the production CLI remains version 0.1.0 and has no temporary-access implementation yet. Its parent baseline is commit `7e95857`.

## Read first

Read applicable `AGENTS.md` files, then these documents in order:

1. [CONTRIBUTING.md](CONTRIBUTING.md): compatibility, security, language, testing and contribution requirements.
2. [SECURITY.md](SECURITY.md): the existing login-agent threat model and recovery safeguards. Update its claims as part of shipping the new feature.
3. [README.md](README.md): current user workflows, commands, file locations and upgrade promises.
4. [Phase 2 design](docs/phase-2-temporary-credentials.md): the agreed CLI, certificate architecture, inventory, aliases, lifecycle, cleanup and recovery requirements. Implement its acceptance cases in addition to this prompt.
5. [Phase 1.5 design](docs/phase-1.5-emergency-kit.md): the implemented kit/inventory/recovery behavior that must remain compatible, plus planned CA integration.
6. [AI agent workflow](docs/ai-agents.md): discoverability, machine-readable output, exact SSH argv and failure handling.
7. [Validation report](docs/phase-2-validation.md) and [disposable probe](scripts/verify-temporary-access-design.py): measured protocol evidence and explicit gaps. The probe uses a real Secure Enclave CA **without biometric flags**, solely for isolated testing. Its signing policy and server loop are not production implementations.

[Windows research](docs/windows-port.md) is background for a separate effort. Windows, WSL, FIDO support, a GUI, a hosted service and new dependencies are outside this implementation.

The specific Phase 2 authorization here permits an explicitly approved temporary software identity while preserving the existing login key's hardware and per-signature Touch ID guarantees. Reflect this distinction in CONTRIBUTING.md and SECURITY.md. Do not apply the temporary identity's behavior to the main key.

## Product outcome

The user or AI requests a set of hosts for a stated duration, approves **one Touch ID** to issue one certificate, and then makes repeated SSH connections without further Touch ID prompts during that grant. This works during the day and overnight. The selected accounts' permissions determine what remote work is possible.

The trust model has three durable public entries on an enrolled target: the existing login key, existing recovery key and a scoped CA trust line. The CA private key stays in this Mac's Secure Enclave. Each grant creates a fresh Ed25519 private key in the temporary process's memory and a short-lived certificate signed by the CA. Servers validate certificates with the public CA they already trust.

## Required command surface

```text
touchid-ssh-agent authorize HOST --temporary-access
touchid-ssh-agent access HOST[,HOST...] --for DURATION [--force-command COMMAND] [--allow-pty] [--json]
touchid-ssh-agent access status [--json]
touchid-ssh-agent access stop [--json]
touchid-ssh-agent access cleanup [--json]
touchid-ssh-agent access help
touchid-ssh-agent access --help
touchid-ssh-agent instructions
```

- Accept hosts directly; no profiles or required `start` verb. Keep normal `authorize` options and behavior compatible when adding its opt-in flag.
- Support inventory/SSH aliases, explicit `user@host` and comma-separated sets. Trim item whitespace, reject empty/option-like inputs, resolve and deduplicate by enrolled target identity, and fail ambiguous matches. Nonstandard ports can use existing SSH aliases in this version.
- Validate every requested destination before requesting Touch ID. Do not silently omit a failed destination or broaden scope. Unknown or unenrolled hosts produce an actionable enrollment error; `access` never silently installs CA trust.
- Require a positive explicit `--for`, such as `30m` or `2h`, with a 12-hour maximum. Display exact local expiry and time zone; JSON uses UTC. Absolute `--until` and automatic renewal are outside the first version.
- Permit one active grant. Return a stable `access_already_active` error with its details on another issuance attempt. Reuse an appropriate grant through status; replacing or extending it requires stopping it and a new approval.
- Default to arbitrary commands within the selected accounts, with `--force-command` optional for fixed tasks. Apply one common permission set across selected targets.
- Default to no PTY, forwarding of any kind or user RC. `--allow-pty` enables only PTY. Do not add forwarding flags in this version.
- Validate options strictly, including subcommand/host ambiguity. Keep user-facing output, errors and documentation in English.

## CA enrollment and scope

- Add a distinct persistent CA identity protected by Secure Enclave `current-set` biometry. Preserve the existing login files and format (`identity.se`, `id_ecdsa_se.pub`, `agent.sock`). Reuse the CA across grants.
- `authorize --temporary-access` explicitly adds CA trust once, using currently working SSH access. Integrate CA creation/enrollment into that flow without requiring users to manage profiles or sign certificates manually.
- Allocate a stable opaque principal for each server/account target. The server's CA line accepts only its target principal, with the agreed restrictions. Never use a shared generic `overnight` principal across all targets.
- One certificate lists all selected target principals, allowing one CA signature and one Touch ID for the whole set. A server trusting the same CA under an unselected principal must reject it.
- Verify the server host key against recorded trust and preserve the exact account, port, principal and restrictions. Detect incompatible server policies without claiming successful enrollment.
- The existing `AuthorizedKey` has no options field. `RemoteKeys.installScript` and `checkScript` match only the public-key blob. Extend these capabilities appropriately: blob presence alone cannot prove scoped CA trust. Handle duplicates, broader trust and option preservation without modifying unrelated keys.

## Certificate and temporary process

- Use deployed OpenSSH `ssh-ed25519-cert-v01@openssh.com` with an Ed25519 temporary key and P-256 Secure Enclave CA signature.
- Implement bounded UInt64 encoding/decoding as needed. Correctly encode the nonce, serial, user type, key ID, nonempty principals, finite validity, critical options, extensions, reserved field and CA key. Sign the complete prescribed byte range. Sort options/extensions, reject duplicates and use nested strings where required.
- Generate a serial atomically under a lock. Use a five-minute `valid_after` clock-skew margin; keep a finite deadline within the duration limit.
- Keep the temporary private key in the isolated job's memory. Do not write its seed/private representation to a file, backup, environment variable, command line or log.
- Never offer the CA on either agent socket. Keep `agent.sock` serving only the normal login identity, with unchanged per-signature Touch ID behavior and protocol surface.
- Support agent requests identifying the temporary key or certificate; return a plain Ed25519 signature blob in both cases. Servers trust the certificate, not the bare temporary key.
- Freeze the validated target/permission/deadline request before showing the summary and signing. Do not re-read mutable scope after approval.
- Run the temporary identity in a separate per-user GUI launchd job with restart disabled. A crash, logout or reboot requires a fresh issuance approval.
- Enforce the deadline before every signature, including requests on pre-existing socket connections; also use a timer and wake checks. Timer delays or clock changes must not extend approved access. Use injectable clocks for tests rather than changing the user's system time.
- Retain socket UID checks, `0700` directories, `0600` sockets, size bounds and input sanitization. A process chain informs the user; it is not an authorization boundary between processes of the same UID.
- Hold an idle-sleep assertion for the grant, release it on termination, and permit the screen to lock. `caffeinate -s` alone applies only on AC power. Do not promise protection against lid closure, forced sleep or power loss.
- Denial, timeout, failed readiness, caller cancellation and abandoned startup must leave no usable partial grant. Coordinate readiness/cancellation with the job so an interrupted CLI does not silently leave a newly issued grant running.
- Return success only after every selected target authenticates with the temporary certificate. Readiness checks must avoid executing remote commands or a forced task: authenticate without requesting a shell/exec/subsystem, then close the connection. Other keys and master connections must not satisfy this check.

## Inventory and compatibility

- Extend `InventoryEntry` with optional temporary-access data so older inventories remain readable. Record CA public key/fingerprint, target ID/principal, exact options, enrollment time and last audit result. Include durable trust in the existing encrypted inventory backup.
- Keep only a bounded latest-grant summary per target: grant ID, serial, temporary public fingerprint, alias, times, permissions and ending reason. Live paths/process identity belong in the local grant manifest. Never back up either private key or restore a live grant from inventory.
- Persist pending CA rotation identities and verified progress until old trust removal completes. Do not lose the old CA fingerprint by overwriting it prematurely with the new one.
- Serialize inventory read/modify/write across authorize, audit, recover, issuance, expiry and cleanup. A background callback must not overwrite newer server records from a stale snapshot.
- Extend `inventory`, `status`, `audit`, `deauthorize` and migration guidance to reflect enrolled CA trust and pending recovery. Audit must validate scope/options, not only fingerprint presence.
- Preserve existing keys, settings, SSH aliases, kit behavior and backup safeguards. An upgrade must not require re-enrolling existing servers unless the user explicitly opts into temporary access.

## Dated aliases and cleanup

- Give each target an alias such as `app-server-access-20261015-a1b2c3d4e5f6`. Use a sanitized bounded literal label, local date and unique grant identifier. Check collisions and do not reuse a grant's alias/path to redirect old commands to another grant.
- Store files under a private, unique directory such as `~/.touchid-ssh-agent/access/grants/<grant-id>/`: socket, public key, certificate, `ssh_config` and ownership manifest. Validate Unix socket path length before approval, including custom data directories.
- Leave the personal `~/.ssh/config` unchanged. Return exact argv such as `["ssh", "-F", "<absolute-grant-config>", "<dated-alias>"]`. An old explicit `-F` command must fail after its config is removed rather than falling back to another grant, DNS or personal keys.
- Generated config selects only the intended temporary identity/certificate, uses public-key authentication and BatchMode, disables forwarding and connection sharing, and preserves verified transport/host-key settings.
- `IdentityAgent` overrides `SSH_AUTH_SOCK`; environment changes alone do not select this feature. A personal `Include` may accumulate identities from `Host *`. A single-Include convenience mode is deferred.
- Preserve supported transport settings without importing other credentials. If temporary authentication is required on a jump host, it must also be explicitly selected/enrolled. Fail unsupported combinations clearly.
- Automatically remove only owned generated artifacts on expiry, stop and failed starts. Sweep stale artifacts before a new grant; offer the same sweep as `access cleanup`. Keep `access status` read-only.
- Validate ownership/manifests, reject path/symlink escapes and unexpected entries, serialize cleanup with grant lifecycle, and keep live unexpired grants. Check process identity, not PID alone. Skip uncertain cases with a reason.
- Cleanup does not remove durable inventory enrollment or remote CA trust. Stop/expiry/revocation do not terminate already authenticated connections or remote work.

## AI integration and help

- Add a distinct **Temporary access** group to root help, plus detailed `access help`/`access --help` covering enrollment, inventory, aliases, returned `-F` commands, cleanup and limitations.
- Ship concise Markdown in `instructions` directly from the installed executable. Keep [docs/ai-agents.md](docs/ai-agents.md) and its copyable AGENTS.md/CLAUDE.md discovery block consistent.
- Issuance/status/stop/cleanup `--json` output is exactly one stdout JSON document, with `schema_version`, `ok`, `status`, stable `error.code`/message on failure, and nonzero failure exit codes. Put human summaries/progress on stderr, with no ANSI or prose mixed into JSON.
- Active results include canonical targets, permissions, grant ID, UTC expiry, remaining seconds, config path, dated aliases and exact per-target `ssh_argv`. Cleanup identifies removed/skipped grants and reasons.
- Guidance must tell the AI to inspect status, reuse suitable access, request the smallest useful scope/duration, wait for actual approval/result and use returned argv. Denial/expiry must not cause retry loops, silent extension, stopping unrelated work or fallback to main/emergency identities.

## Recovery is part of completion

Implement the [required CA recovery sequence](docs/phase-2-temporary-credentials.md#required-recovery-sequence-for-ca-trust) as an integrated part of `recover`:

1. Open the kit/inventory and identify old CA public identities. Create or reuse the new Mac's distinct CA. The old CA private key is neither recoverable nor needed for removal. Targets without enrollment retain the current recovery path.
2. Persist per-target intent/progress before mutations, retaining old/new identities and scope. Preserve pre-recovery backups and partial-failure safeguards.
3. Through emergency access and verified host keys, add replacement login/emergency keys and new scoped CA trust. Verify the new login and actual certificate authentication through the new CA using a short-lived, internal memory-only validation credential. Explain the associated issuance approval; do not publish it as a normal access grant.
4. Only after replacement checks pass on that target, remove retired login/emergency keys as applicable and old CA trust by exact recorded identity. Protect current new keys and unrelated entries. Verify old CA absence and new CA scope, then commit/audit that target's progress.
5. Unreachable, unverified or incompletely cleaned targets stay pending. Retry must finish their CA steps even when login/emergency fingerprints already match the new Mac. The current skip predicate needs extension for this condition.
6. `--keep-emergency-key` affects only the emergency key, not retirement of the lost Mac's CA. `recovery test` remains read-only and reports recorded CA trust. Update kit/manual-recovery instructions to identify and remove old CA trust using inventory.
7. Do not restore old temporary keys, sockets, dated aliases or active grants. Report unmanaged additional CA trust paths honestly; removing one managed line does not prove revocation through every other server configuration.

## Implementation map

| Files | Starting points and responsibilities |
| --- | --- |
| [Package.swift](Package.swift), [Makefile](Makefile) | Swift 5.10/macOS 13 baseline; no Swift dependencies; build/test entrypoints. |
| [CLI main](Sources/touchid-ssh-agent/main.swift) | Dispatch, grouped help, parsing, status, existing config command. Add dedicated command files rather than growing all behavior here. |
| [RecoveryCommands.swift](Sources/touchid-ssh-agent/RecoveryCommands.swift) | `authorize`, `runAudit`, `listInventory`, recovery/status integration and SSH config prompts. |
| [RecoverCommand.swift](Sources/touchid-ssh-agent/RecoverCommand.swift) | `recover`, current already-moved skip predicate, `recoverServer`, emergency checks, backup preservation and final audit. |
| [DeauthorizeCommand.swift](Sources/touchid-ssh-agent/DeauthorizeCommand.swift), [MigrateCommand.swift](Sources/touchid-ssh-agent/MigrateCommand.swift) | Key removal, inventory handling and migration guidance that must include CA state. |
| [IdentityStore.swift](Sources/TouchIDSSHCore/IdentityStore.swift), [Signer.swift](Sources/TouchIDSSHCore/Signer.swift) | Paths, Secure Enclave identities/policies, fresh LAContext and existing per-signature signer. Preserve main-key protection. |
| [SSHWire.swift](Sources/TouchIDSSHCore/SSHWire.swift), [SSHKeyFormat.swift](Sources/TouchIDSSHCore/SSHKeyFormat.swift), [AgentProtocol.swift](Sources/TouchIDSSHCore/AgentProtocol.swift) | Reusable bounds-checked codec, P-256 encoding, fingerprints and limited agent protocol. |
| [AgentServer.swift](Sources/TouchIDSSHCore/AgentServer.swift), [LaunchAgent.swift](Sources/TouchIDSSHCore/LaunchAgent.swift) | Existing transport is tied to StoredIdentity/P-256. Share appropriate infrastructure while keeping the temporary process, CA and normal agent isolated. |
| [PeerProcess.swift](Sources/TouchIDSSHCore/PeerProcess.swift), [PromptText.swift](Sources/TouchIDSSHCore/PromptText.swift), [SignedPayload.swift](Sources/TouchIDSSHCore/SignedPayload.swift) | Peer UID/process context, sanitized UI/log text and current authentication-payload classification. |
| [Inventory.swift](Sources/TouchIDSSHCore/Inventory.swift) | Codable compatibility, stores, atomic saves and age-encrypted inventory backup. Add shared update serialization. |
| [RemoteKeys.swift](Sources/TouchIDSSHCore/RemoteKeys.swift), [SSHConfig.swift](Sources/TouchIDSSHCore/SSHConfig.swift) | Destination resolution, key representation/options, installation/audit/removal, host-key trust and config handling. Preserve unrelated configuration. |
| [Command.swift](Sources/TouchIDSSHCore/Command.swift), [RecoverySupport.swift](Sources/TouchIDSSHCore/RecoverySupport.swift), [Recovery.swift](Sources/TouchIDSSHCore/Recovery.swift) | Safe process/file operations, emergency agent, pinned hosts, kit creation and embedded manual instructions. |
| [Output.swift](Sources/touchid-ssh-agent/Output.swift), [Terminal.swift](Sources/touchid-ssh-agent/Terminal.swift) | Human output and interaction; keep machine stdout separate. |
| [SelfTest](Tests/SelfTest/main.swift), [Dockerfile](Tests/e2e/Dockerfile), [container entrypoint](Tests/e2e/entrypoint.sh) | Existing executable test harness, expect-driven flows and disposable sshd. Use these patterns; XCTest requires more than the project's Command Line Tools baseline. |
| [manual-touchid-test.sh](scripts/manual-touchid-test.sh) | Existing interactive validation under launchd; extend or add equivalent temporary-access/CA coverage. |

## Execution and validation

Inspect the working tree and preserve unrelated user changes. Implement in coherent commits on an appropriate `codex/` feature branch unless the user supplied another branch/worktree. Use the E1–E5 deliverables in the design, handling dependencies as needed; completion requires the full inventory/recovery/AI workflow, not only certificate generation. Keep a brief implementation/validation record with completed and pending acceptance checks.

Required validation for the implementation:

```bash
make build
make test
make test-docker
python3 -B scripts/verify-temporary-access-design.py
make test-touchid
```

- Run the noninteractive checks against disposable state/servers. Keep automated keys without user presence exclusively in test-only isolated directories. Never point tests at the installed identity directory, real inventory or real hosts.
- Cover comma parsing/errors, multiple principals, valid/expired/malformed certificates, forced commands, default permissions/PTY opt-in, bare-key rejection, JSON stdout, aliases/path escaping, config isolation and absence of authentication fallback.
- Test lifecycle denial/timeout/cancellation, startup failure, crash, connected-client expiry, clock changes, cleanup races/ownership and legacy inventory compatibility. Check native SSH interoperability rather than only decoding your own output.
- Cover CA enrollment/audit/deauthorization and full/interrupted recovery. Before rotation, a valid old certificate must authenticate; after verified replacement and old CA removal it must fail **fresh** authentication while replacement keys/new CA work. Verify retries do not skip pending CA work.
- Real biometric approval, denial/timeout, launchd, locked-screen operation and idle-sleep handling require interactive validation in addition to tests with unprotected keys. Arrange human participation for these checks; do not lock the user's screen, change enrolled fingerprints or simulate sensor approval automatically. Complete independent work and report any manual checks still pending.
- Logs must not contain private material, payloads, hosts or remote account names. Never put emergency passphrases in argv/environment. Do not weaken ACLs or introduce a main-key reuse window to pass tests.
- Keep README, SECURITY.md, CONTRIBUTING.md, Phase 1.5/2 design notes, installed help/instructions and AI guidance consistent with actual behavior. Mark any remaining unimplemented/manual acceptance items explicitly.
- Check diffs for whitespace, secrets, real infrastructure data and unrelated edits. Do not install/restart the user's real agent, enroll real hosts, publish, push or create external messages as a side effect of implementing/testing.

The final implementation report must state what changed, the commands that actually passed, any failed/pending interactive checks, and the limits of the security model: same-UID processes can use an active grant, the temporary software key may be extractable, and expiry/stop/CA retirement block new authentication rather than terminating existing remote sessions or undoing changes.

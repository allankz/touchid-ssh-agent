# Phase 2 implementation record

> What was built for [temporary SSH access](phase-2-temporary-credentials.md), how each acceptance gate was checked, and what still needs a person at the Mac. Implemented on branch `codex/phase-2-temporary-access` from the handoff in [`PROMPT-PHASE-2.md`](../PROMPT-PHASE-2.md), on macOS 26.4.1 with OpenSSH 10.2p1 (client) and OpenSSH 10.0p2 (Docker servers). It ships as version 0.2.0.

## What changed

| Area | Files | What it does |
| --- | --- | --- |
| Certificates | `SSHWire.swift`, `SSHCertificate.swift` | `uint64` encoding; Ed25519 user certificates with validated principals, finite validity, sorted unique options, nested `force-command`, and the CA signature over every field. |
| CA | `CertificateAuthority.swift`, `IdentityStore.swift` | A second Secure Enclave key (`ca.se`, `ca.pub`), always `current-set`; locked serial counter (`ca.serial`); issuance helper that verifies the signature before use. Login key files and format unchanged. |
| CA trust lines | `CATrust.swift`, `RemoteKeys.swift` | `AuthorizedKey` gains options; authorized_keys option parsing; scope classification (exact, narrower, broader), duplicates, retired and unmanaged CAs. Installation never edits existing lines. |
| Inventory | `Inventory.swift`, `FileLock.swift` | Optional `temporaryAccess` per entry (scope, verification, latest grant, CA rotation progress, retired CA). Every writer merges under `inventory.lock`. |
| Grant | `AccessGrant.swift`, `AccessJob.swift`, `AccessControl.swift`, `TemporaryAgent.swift`, `PowerManagement.swift`, `LaunchAgent.swift` | Frozen request with digest, manifest, dated aliases, isolated `ssh_config`, ownership-checked cleanup; the grant job (launchd label per grant, no restart), its control socket, the in-memory Ed25519 agent with a two-clock deadline, the idle-sleep assertion and wake checks; the authentication-only readiness check. |
| Validation certificate | `CertificateValidation.swift` | A short-lived, memory-only certificate (`force-command true`) used by `authorize --temporary-access` and `recover` to prove a server accepts the CA. Never published as a grant. |
| CLI | `AccessCommand.swift`, `Instructions.swift` (also `instructions --snippet` and `--add-to FILE`, which put the AI discovery block in `CLAUDE.md`, `AGENTS.md` or similar after asking), `TemporaryAccessSetup.swift`, `RecoverCA.swift`, `RecoveryCommands.swift`, `RecoverCommand.swift`, `DeauthorizeCommand.swift`, `MigrateCommand.swift`, `main.swift` | `access` and its subcommands, `instructions`, `authorize --temporary-access`, CA-aware `audit`, `inventory`, `status`, `deauthorize`, `migrate` and `recover`; the Temporary access help section. |
| Kit | `Recovery.swift` | New kits explain how to remove the lost Mac's CA by hand. |
| Tests | `Tests/SelfTest/AccessTests.swift`, `Tests/SelfTest/AccessDockerTests.swift`, `Tests/e2e/*`, `scripts/manual-touchid-test.sh` | Unit, Secure Enclave, Docker and interactive coverage below. The e2e sshd disables `PerSourcePenalties` (the tests fail logins on purpose from one NAT address) and accepts a test-only `SSHD_EXTRA`. |
| Docs | `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/*` | Behavior, threat model, the explicit temporary-key exception, AI workflow and limits. |

## Acceptance gates

| Gate | Evidence |
| --- | --- |
| E1: CA, inventory, enrollment, audit, deauthorize, recover | Docker: *authorize --temporary-access: one scoped CA line per server, distinct principals, inventory and backup*; *audit checks the CA scope*; *deauthorize removes the CA line*; *a server that refuses certificates is recorded unverified*; *a replaced CA*; the five *Recovery of temporary-access CA trust* tests. Unit: *CA: separate Secure Enclave key, never on the login agent's socket*; *inventory: older files load*. |
| E2: certificate builder, Ed25519 agent, P-256 CA | Unit: `ssh-keygen -L` reads every field; signature covers every field (tampering any region fails both our check and `ssh-keygen`); invalid fields refused; parsing `ssh-keygen`'s own certificates; fuzzed malformed input; Secure Enclave CA signature accepted by `ssh-keygen`. Docker: real `sshd` logins with the certificate. |
| E3: job, grant directories, cleanup | Unit (in-process job): denial, timeout, abandoned start, vanished caller mid-prompt and digest mismatch publish nothing; abort, stop and clock-driven expiry remove everything. Docker: crash and cleanup, interrupted CLI, expiry with a held agent connection, launchd job. Unit cleanup test: manifests, symlinks, unexpected files, reused pids. |
| E4: CLI, aliases, JSON, help, instructions | Docker: error cases emit one JSON document and the right exit code before any grant exists; returned argv used for repeated commands; personal `~/.ssh/config` unchanged; old argv fails after stop. Unit: generated config checked with `ssh -G`, unknown names fail offline, removed config fails. |
| E5: real servers, interactive checks, release docs | Docker suites and the feasibility probe pass; `make test-touchid` passed 14/14 with real Touch ID. Still unchecked by hand: see [Pending](#pending-manual-checks). |

## Required cases

| Case (from the design) | Covered by |
| --- | --- |
| One host and comma lists; whitespace, empty items, duplicates, ambiguity; validation before approval | Docker *access: unknown, unenrolled, ambiguous and malformed requests…* and *one approval for two targets* (`"srv-a, srv-b,e2e-a"` collapses to two targets). Nonstandard ports go through ssh aliases (all Docker servers use mapped ports). |
| One Touch ID for several targets; denial, timeout, abandoned or failed start publish nothing | Docker log check (one `issued` per grant); in-process job tests. Real prompts: `make test-touchid` steps 6–8 (passed). |
| Repeated commands without more Touch ID; other identities and master connections cannot satisfy readiness | Docker repeated-command test; *the readiness check is not satisfied by another key*; the grant config forces `ControlPath none` and `IdentitiesOnly`. |
| Unselected principal, bare key, expired and malformed certificates rejected | Docker (`-o Port` to the third server, `PubkeyAcceptedAlgorithms=ssh-ed25519`), expiry test, unit tampering tests. |
| `force-command` wins; default denies PTY and forwarding; `--allow-pty` enables only PTY | Docker *--force-command and --allow-pty* (forwarding tried with `ClearAllForwardings=no`), plus the default-grant PTY and `-R` checks. |
| New authentication fails after expiry; existing connections survive | Docker expiry test (an `ssh` started before expiry finishes after it). |
| Stop, crash, sleep/wake, delayed timers, clock changes, connected clients | Docker stop and crash tests; unit clock tests (wall clock set back with the monotonic clock advanced, wall clock jumped forward, held connection refused). Real sleep/wake: pending. |
| JSON consistency; instructions match the CLI; denial causes no prompt loop | Docker JSON envelope checks; `access` never retries a prompt (one job, one prompt). |
| Audit and recovery rotate CA trust without touching unrelated keys | Docker audit and recovery tests (bootstrap key preserved, duplicates removed, other CA lines counted, not removed). |
| A still-valid old certificate fails fresh authentication after old-CA removal | Docker *recover, interrupted…*: the old Mac's live grant works before and fails after, on a server where the new CA verified and on the one whose run was interrupted; *recover again…*: new CA, login and emergency keys work. |
| Interruption after new-key installation, new-CA verification or partial old-CA removal resumes; fingerprint matches alone never skip CA work; offline targets stay pending | Docker: the cert-refusing server stays pending with old trust; the retry from a simulated half-finished state (login moved, old emergency key gone, old CA present) is not skipped and finishes through the Touch ID key. |
| Read-only `recovery test`; old inventories; `--keep-emergency-key`; duplicate old lines; failed new-CA check (old credentials still removed, enrollment unconfirmed); interrupted run resumed; no grants restored | Docker recovery tests; the existing Phase 1.5 recover tests (inventories without CA fields). |
| Inventory round trip, older files, backup holds durable trust, no live grant restored | Unit inventory tests; Docker backup decryption checks. |
| Dated aliases unique, mapped to the right account, not replacing permanent aliases; old `-F` commands cannot reconnect | Unit names and `ssh -G` tests; Docker stop test. |
| Cleanup preserves personal config, user files and live grants; uncertain ownership skipped | Unit cleanup test; Docker crash test; *the personal ssh config is never changed*. |
| Help section; detailed help and instructions | Docker *access help*; root help shows the Temporary access section. |

## Commands run

Final runs on this branch (2026-10-15), with the Mac unlocked:

| Command | Result |
| --- | --- |
| `make build` | Passed (release build). |
| `make test` | Passed: 57 tests (the 37 earlier tests unchanged, plus 20 new unit, Secure Enclave, in-process job and instructions tests). |
| `make test-docker` | Passed: 98 tests (the 57 above plus 41 Docker tests, of which 16 cover temporary access and 5 CA recovery). |
| `python3 -B scripts/verify-temporary-access-design.py` | Passed (the feasibility probe still works with the changed codec files and e2e image). |
| `LAUNCH_ONLY=1 make test-touchid` | Passed: the agent runs under launchd and offers the test identity. |
| `make test-touchid` (interactive) | Passed: 14/14 with a person at the Mac (2026-10-15, before the final-review fixes; not run again after them). Login key: approve, deny, time out, approve again, all under launchd. Temporary access: enrollment with a real `current-set` CA (login check and validation certificate approved), issuance through the per-grant launchd job, three logins without prompts, the idle-sleep assertion held and released, the old command failing after stop, `approval_denied`, `approval_timeout`, and no grant directory or job left. |

`swift run touchid-ssh-agent-selftest --docker --access-only` runs only the temporary-access and CA-recovery Docker tests.

## Final review before release

Two independent read-only reviews (recovery safety, and upgrades for 0.1.0 users who never use temporary access) found no problem for those users, and these problems in recovery and elsewhere, all fixed:

| Problem | Fix | Test |
| --- | --- | --- |
| `recover` saved servers only at the end, so an interrupted run could leave a moved server unrecognized, with the kit unable to reach it | Each server's record is saved as soon as it is done; a server whose record shows an interrupted run is finished through the new Touch ID key | Docker: a real run is interrupted (test-only `TOUCHID_SSH_AGENT_TEST_INTERRUPT`) right after a server's old keys are removed, the kit's key is then removed there, and the next run finishes it through the Touch ID key |
| A failed certificate check through the new CA kept every old credential, including the lost Mac's login key | Once the new login works, the lost Mac's login key, the used emergency key and every lost-Mac CA are removed; the new CA is recorded as unconfirmed for `authorize --temporary-access` (a deliberate change to the original design, approved during the review) | Docker: a server refusing certificates loses all old credentials, `access` refuses it, and `authorize --temporary-access` confirms it later |
| A server already finished for the CA but not skipped could fail its check (principal missing from the validation certificate) or lose its record | CA steps run only where CA work is pending; other servers keep this Mac's record | Covered by the resumed run |
| A server enrolled on the new Mac before `recover` was skipped while the lost Mac's CA stayed | Complete means every recorded lost-Mac CA is recorded as removed | Docker: the new Mac enrolls a server first; `recover` removes the old CAs and keeps the new Mac's principal |
| Only one old CA was retired when the lost Mac had left a CA replacement unfinished | All recorded CAs (enrolled and both sides of a pending replacement, minus this Mac's) are retired, each checked against its fingerprint | Docker: the same server also trusts the CA the lost Mac was replacing |
| A later command could rewrite the backup the kit opens before a retry | A dated copy is kept as soon as RECOVER is typed (an identical copy is reused) | Docker: the copy exists and matches the original backup |
| A second grant job on a live grant's directory deleted its files | A job leaves a directory alone unless it owns it | Unit: a second job and a wrong digest leave a live grant untouched |
| Plain `authorize` required the server listing (new precondition) | Without `--temporary-access`, the 0.1.0 install script again | Existing authorize tests |
| `migrate` suggested `access stop` to everyone; lock errors were misreported on file systems without `flock` | Shown only when temporary access is in use; unsupported `flock` proceeds unlocked, as before the lock | — |

Known limitation, unchanged from 0.1.0: a command on the new Mac that writes the backup before `recover` runs (for example `authorize` with the same backup folder configured) replaces the old Mac's `inventory.age`. Run `recover` first on a new Mac.

## Pending manual checks

`make test-touchid` covered real Touch ID approval, denial and timeout for the login key and for CA issuance under launchd. These still need a person, because they change the user's session:

- Locked-screen operation: request a grant, lock the screen (⌃⌘Q), and from another machine or an existing session run the returned command; it should keep working while locked.
- Sleep and wake: with a short grant, sleep the Mac past the deadline; after wake no signature may be produced and the grant files must be gone within a few seconds.
- Logout: logging out must end the grant job (it is not restarted at the next login).

## Security limits

- Any process of the user can use an active grant through its socket; the requester shown in the log is informational.
- The temporary key is a software key in the job's memory and may be extractable by malware running as the user; stopping the grant cannot destroy a copy, which stays usable until the certificate expires or the CA line is removed.
- Expiry, stop and CA retirement block new authentication only. They do not end sessions already open or undo remote changes; a grant is not a sandbox.
- Only the `authorized_keys` line this tool manages is audited, rotated or removed; other trust paths on a server are reported as unchecked.
- Jump hosts and proxy commands are not supported yet.

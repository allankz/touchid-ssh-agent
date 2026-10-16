# Release notes

## 0.2.0 — 2026-10-15

Tag `v0.2.0`, merged into `main` on 2026-10-16 through [allankz/touchid-ssh-agent#1](https://github.com/allankz/touchid-ssh-agent/pull/1).

These notes compare 0.2.0 with 0.1.0 as it stood at commit `69ecddc` (2026-10-09), the last 0.1.0 state before Phase 2. 0.1.0 was never tagged.

Still experimental. Keep the emergency key installed on every server (`touchid-ssh-agent audit`).

### Highlights

- **Temporary SSH access for AI agents.** Approve selected servers once, with one Touch ID, for up to 12 hours, and let an agent make repeated SSH connections while you are away: `touchid-ssh-agent access app-server,worker-server --for 2h`. Your login key keeps asking for Touch ID on every use.
- **Instructions for AI agents, built into the CLI.** `touchid-ssh-agent instructions` prints the workflow for the installed version, and `instructions --add-to ~/.claude/CLAUDE.md` (or `~/.codex/AGENTS.md`) points your agent to it.
- **Safer recovery.** `recover` now saves each server as soon as it is done, resumes an interrupted run, keeps a dated copy of the backup it opens, and removes the lost Mac's temporary-access CA.

### Upgrading from 0.1.0

```bash
git pull
make install
launchctl kickstart -k gui/$(id -u)/local.touchid-ssh-agent
touchid-ssh-agent version    # 0.2.0
```

The upgrade is additive:

- Your Touch ID key, emergency kit, inventory, backup folder and the keys on your servers keep working. Nothing on a server changes until you run `authorize HOST --temporary-access` for it.
- Plain `authorize` (without `--temporary-access`) installs keys with the same script as 0.1.0.
- The inventory only gains an optional `temporaryAccess` field per server; inventories written by 0.1.0 load as before.
- Emergency kits created before 0.2.0 describe how to remove the lost Mac's login key only. Kits created by 0.2.0 also explain how to remove its temporary-access CA by hand.
- If you set `TOUCHID_SSH_AGENT_DIR`, keep it short: grant sockets live four levels below it, and Unix socket paths are limited to 104 bytes (`access` fails with `socket_path_too_long`).
- The binary now also links IOKit (to keep the Mac from idle-sleeping during a grant). There are still no Swift dependencies, and `age` is still the only external tool.

New files in `~/.touchid-ssh-agent/`. Only `inventory.lock` appears for everyone; the others arrive with the CA and with grants:

| File | What it is |
| --- | --- |
| `ca.se`, `ca.pub`, `ca.serial` | The temporary-access CA (a second Secure Enclave key), its public key and certificate serial counter. Created by the first `authorize --temporary-access`. |
| `access/grants/GRANT-ID/` | One grant's socket, public key, certificate, `ssh_config`, pinned `known_hosts` and ownership manifest. Removed when the grant ends. |
| `access.log`, `access.stderr.log` | Grant events: issuance, signatures, expiry and stop. No keys, payloads, hosts or accounts. |
| `inventory.lock`, `ca.serial.lock`, `access/lifecycle.lock` | Empty lock files that keep concurrent commands from overwriting each other. |

### New: temporary SSH access

**Enroll each server once**, with the access you already have:

```bash
touchid-ssh-agent authorize app-server --temporary-access
```

This adds one line to the account's `authorized_keys`, next to the login and emergency keys: this Mac's CA, trusted only for that account's own principal, with agent, port and X11 forwarding and user rc files denied. After the usual Touch ID login check, it checks a real certificate login (one more Touch ID, for a validation certificate that grants nothing) and records the CA trust in the inventory and its encrypted backup. Existing lines are never edited, and a CA line with broader options is reported and refused. The server's host key must already be in `known_hosts`.

**Request access.** One Touch ID approves one certificate for every server you list:

```bash
touchid-ssh-agent access app-server,worker-server --for 2h
```

- Servers can be inventory names, ssh aliases or `user@host`. Every one is checked before Touch ID; one unknown or unenrolled server fails the whole request.
- `--for` is required and accepts durations such as `45s`, `30m`, `2h` or `1h30m`, up to 12 hours.
- The summary shows each account, the exact expiry (local time and UTC) and the permissions before you approve.
- Commands are unrestricted within the selected accounts unless you pass `--force-command COMMAND`. No PTY unless `--allow-pty`. Agent, port and X11 forwarding are always denied.
- A one-shot launchd job generates a fresh Ed25519 key in its own memory, has the CA sign a certificate for it, and checks that every server accepts it before the grant is reported as active. One grant is active at a time.

**Use it.** Each server gets a dated alias, such as `app-server-access-20261015-a1b2c3d4e5f6`, defined in the grant's own `ssh_config`. Your `~/.ssh/config` is not changed:

```bash
ssh -F ~/.touchid-ssh-agent/access/grants/20261015-a1b2c3d4e5f6/ssh_config app-server-access-20261015-a1b2c3d4e5f6 uptime
```

That config offers only the grant's key and certificate, pins the host keys from the inventory, and disables forwarding and connection sharing. `access status` prints the exact commands.

**When it ends.** At expiry or after `access stop`, the job stops signing and removes its socket, key, certificate and config, so old commands fail instead of falling back to other keys. Servers reject the certificate after its expiry on their own. A crash, logout or reboot also ends the grant, and nothing restarts it; `access cleanup` (or the next request) removes what it left. While a grant is active, the Mac does not idle-sleep (the screen still locks).

| Command | What it does |
| --- | --- |
| `authorize HOST --temporary-access` | Enrolls a server: installs and verifies this Mac's CA there, once. |
| `access HOST[,HOST...] --for DURATION [--force-command C] [--allow-pty] [--json]` | Requests a grant; one Touch ID approves issuance. |
| `access status [--json]` | Validity, targets, aliases and exact SSH commands. Never prompts. |
| `access stop [--json]` | Stops the active grant and removes its local files. |
| `access cleanup [--json]` | Removes files left by grants that ended abnormally; keeps live, valid grants. |
| `access help` | Enrollment, aliases, cleanup and limits in detail. |

**JSON for scripts and agents.** With `--json`, each `access` command writes one JSON document to stdout (`schema_version` 1, `ok`, `status`); progress and the approval summary go to stderr. SSH commands come as argv arrays (`ssh_argv`), not shell strings. Errors carry a stable `error.code` and exit 1, except `invalid_arguments` and `invalid_duration`, which exit 2. The codes are: `invalid_arguments`, `invalid_duration`, `unknown_target`, `not_enrolled`, `ambiguous_target`, `ca_mismatch`, `rotation_pending`, `host_key_missing`, `unsupported_configuration`, `socket_path_too_long`, `access_already_active`, `access_busy`, `approval_denied`, `approval_timeout`, `approval_unavailable`, `ca_unusable`, `cancelled`, `stopped`, `readiness_failed`, `job_failed`, `stop_failed`, `internal_error`.

**If the CA stops working.** The CA always uses the `current-set` policy, so adding or removing a fingerprint invalidates it and `access` fails with `ca_unusable`. Move `ca.se` and `ca.pub` out of `~/.touchid-ssh-agent`, then run `authorize HOST --temporary-access` for each enrolled server: the first run creates a new CA, and each run installs it, checks it and removes the old one from that server.

### New: instructions for AI agents

| Command | What it does |
| --- | --- |
| `instructions` | Prints, in Markdown, the temporary-access workflow for the installed version: check `access status --json`, request the fewest servers for the shortest time, wait for Touch ID, run exactly the returned `ssh_argv`, and what to do on each error. |
| `instructions --snippet` | Prints a short block for `CLAUDE.md`, `AGENTS.md` or similar that tells the agent to run `instructions`. |
| `instructions --add-to FILE` | Adds that block to `FILE` after showing it and asking, or updates the block it added before. The rest of the file is kept byte for byte. |

The main help now starts with a line pointing AI agents to `instructions`. The same workflow is in [`docs/ai-agents.md`](docs/ai-agents.md).

### Changes to existing commands

- **`help`**: a new *Temporary access* section, and a pointer to `instructions` for AI agents.
- **`status`**: also shows the temporary-access CA, pending CA replacements and the active grant.
- **`inventory`**: also shows each server's temporary-access enrollment and latest grant.
- **`audit`**: on enrolled servers, also checks that the CA line keeps its scope (principal and restrictions), not only that the key is present.
- **`deauthorize`**: also removes this Mac's CA line, and a lost Mac's CA still waiting for removal there, matched by the exact key.
- **`migrate`**: shows the CA and the servers that trust it, warns about servers with another CA, an unfinished CA replacement or an unconfirmed enrollment, and says that active grants are not carried over to the new Mac.
- **`recover`**: on enrolled servers, creates this Mac's CA, adds it with the same principal and restrictions, and checks a real certificate login through it (one Touch ID for all servers). Once the new Touch ID login works, every CA of the lost Mac the inventory recorded is removed by its exact key; `--keep-emergency-key` never keeps it. If the certificate check fails, the old credentials are removed anyway and the server is marked "temporary access not confirmed", to finish later with `authorize HOST --temporary-access`. Old grants are not restored.
- **`recovery test`**: also reports each server's recorded CA trust. It still changes nothing.
- **Emergency kit**: kits created by 0.2.0 explain how to remove the lost Mac's CA by hand.
- **`TOUCHID_SSH_AGENT_PROMPT_TIMEOUT`**: also applies to the CA's Touch ID prompts when set in the shell that runs `access`, `authorize` or `recover`.

### Recovery and inventory fixes

These matter even if you never use temporary access:

- `recover` records each server in this Mac's inventory as soon as that server is done. In 0.1.0 it saved them only at the end, so an interrupted run could leave a moved server unrecorded.
- A server left half-moved by an interrupted run is finished on the next run, through this Mac's Touch ID key when the kit no longer opens it.
- Before changing anything, `recover` keeps a dated copy of the backup the kit opens (`inventory-before-recovery-DATE.age`). If a later command rewrote the backup, point `--inventory` at that copy.
- When a server fails, the final audit no longer rewrites the cloud backup. In 0.1.0 it did, despite the message saying the backup was left unchanged, which replaced the old Mac's inventory, the one a retry needs, with this Mac's partial one.
- Every command that writes the inventory now merges its changes under `inventory.lock`, so concurrent commands do not overwrite each other.
- The README now says to run `recover` before `authorize` on a new Mac: once the new Mac's inventory lists a server, its next backup replaces the old Mac's `inventory.age` in a shared backup folder. This limitation is unchanged from 0.1.0.

### Security

Temporary access is the one explicit exception to "Touch ID for every signature": one Touch ID lets a grant's own Ed25519 software key sign SSH logins, for the selected servers only, until a deadline of at most 12 hours. It never applies to the login key or the CA. The login key and the CA both stay in the Secure Enclave, and every certificate the CA issues needs Touch ID.

Limits to know before you use it (details in [`SECURITY.md`](SECURITY.md)):

- Any process of your macOS user can use an active grant through its socket. The requesting process shown in the log is informational.
- The grant's key is a software key in the grant job's memory. Malware running as you could copy it, and a copy works until the certificate expires or the CA line is removed.
- Expiry, `access stop` and CA removal block new logins only. Open sessions, running commands and changes already made continue. A grant is not a sandbox: the selected account's permissions apply.
- Only the CA line this tool installs in `authorized_keys` is audited, rotated or removed. Trust configured elsewhere (for example `TrustedUserCAKeys`) is not checked.
- A server clock that is far off can reject a valid certificate or accept one after its deadline (certificates start five minutes early).
- Closing the lid, a forced sleep or a power loss still interrupt a grant, and the deadline keeps counting meanwhile.
- One grant at a time. Servers behind jump hosts or proxy commands are not supported yet (`unsupported_configuration`).

### Validation

On 2026-10-15, with macOS 26.4.1, OpenSSH 10.2p1 (client) and OpenSSH 10.0p2 (Docker servers):

- `make test`: 57 tests passed (the 37 existing tests plus 20 new).
- `make test-docker`: 98 tests passed, of which 16 cover temporary access and 5 CA recovery.
- `make test-touchid`: 14/14 with real Touch ID, for the login key and for CA issuance under launchd. It ran before the final-review fixes and was not run again after them.

Not checked by hand yet: using a grant while the screen is locked, sleep and wake past the deadline, and logout ending the grant job. A session with an actual AI agent is not part of the automated tests. See the [implementation record](docs/phase-2-implementation.md).

### For contributors

- `swift run touchid-ssh-agent-selftest --docker --access-only` runs only the temporary-access and CA-recovery Docker tests.
- Test-only settings: `TOUCHID_SSH_AGENT_ACCESS_LAUNCH=process` starts a grant's job as a detached process instead of under launchd; `TOUCHID_SSH_AGENT_TEST_INTERRUPT=after-removal:<alias>` makes `recover` exit early, to test resuming.
- The e2e `sshd` image turns off `PerSourcePenalties` (the tests fail logins on purpose from one NAT address) and accepts `SSHD_EXTRA` for per-test settings.
- `make test-docker` and `make test-touchid` now cover temporary access too. Run `make test-touchid` when you touch the CA or the grant job.
- The project principles in [`CONTRIBUTING.md`](CONTRIBUTING.md) now state the temporary-access exception; longer grants, renewal or reuse windows for any other key need an issue first.

### Documentation

- [`docs/ai-agents.md`](docs/ai-agents.md): the AI workflow and the discovery block.
- [`docs/phase-2-temporary-credentials.md`](docs/phase-2-temporary-credentials.md): the design, now marked implemented, with the JSON contract.
- [`docs/phase-2-implementation.md`](docs/phase-2-implementation.md): what was built, how each gate was checked, and the pending manual checks.
- [`docs/phase-2-validation.md`](docs/phase-2-validation.md) and `scripts/verify-temporary-access-design.py`: the protocol feasibility probe.
- [`docs/windows-port.md`](docs/windows-port.md): research notes for a possible Windows version (not scheduled, nothing implemented).
- [`PROMPT-PHASE-2.md`](PROMPT-PHASE-2.md): the handoff Phase 2 was built from.
- README and `SECURITY.md` cover temporary access, the new files, the threat model and the limits. "Coming next" now lists possible temporary-access options: several grants at once, an absolute `--until`, per-server permissions, scoped port forwarding and jump hosts.

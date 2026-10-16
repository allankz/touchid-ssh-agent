# Phase 2: temporary SSH access

> Status: **implemented**. The commands and JSON below describe the shipped contract; [Implementation notes](#implementation-notes) list where the implementation settles details this design left open, and the [implementation record](phase-2-implementation.md) lists what was validated and what still needs a person at the Mac. Prerequisites: Phase 1 validated with real Touch ID (`make test-touchid`) and installed; Phase 1.5 (emergency kit and inventory) in place.

## Goal

Approve temporary SSH access once, then let a person or AI make repeated connections without more Touch ID prompts. Daytime work and overnight work use the same feature. Approval covers **selected server/account destinations, permissions and a deadline**. No profile needs to be created. The main login key continues to require Touch ID on every signature.

The deadline governs **new SSH authentications**. It does not terminate authenticated connections, remote processes or changes already made.

## Why the server accepts a new temporary key

The current login and recovery public keys do **not** authorize an unrelated key. Enabling this feature adds a **third public-key line**, marked `cert-authority`, to the target account's `authorized_keys` once:

| Public key stored on the server | Purpose |
| --- | --- |
| Existing login key | Authenticate normal logins approved with Touch ID. |
| Existing recovery key | Authenticate the emergency kit. |
| New CA key | Verify signed temporary certificates for this target. |

The CA's private key stays in the Mac's Secure Enclave. After a Touch ID approval it signs a certificate stating which temporary public key may authenticate, for which enrolled targets and until when. The temporary private key remains in the local agent's memory. On each login, SSH presents the certificate and proves possession of that temporary key; the server checks the certificate using the CA public key it already trusts.

The temporary key does not need a new `authorized_keys` entry on each grant. The initial CA trust line is what makes subsequent, newly generated keys acceptable. Ordinary SSH certificate support performs the verification; no custom server agent is required. Expired certificates fail new authentication even if the Mac fails to clean up.

This is a one-time trust change on each host/account, not a feature that works with only the existing two lines. A [reproducible validation report](phase-2-validation.md) records the prototype checks and what remains untested.

## Direct-host CLI

```bash
# An existing SSH alias or user@host.
touchid-ssh-agent access app-server --for 2h

# Several destinations, approved together with one Touch ID.
touchid-ssh-agent access app-server,worker-server --for 8h

# Optional restriction for a fixed task.
touchid-ssh-agent access app-server --for 30m --force-command /usr/local/bin/backup

touchid-ssh-agent access status
touchid-ssh-agent access stop
touchid-ssh-agent access cleanup
```

- `access HOST[,HOST...]` starts a grant directly. There is no `start` verb or required profile.
- `--for` is required, accepts positive durations such as `30m`, `2h` and `8h`, and is capped at **12 h**. Display the exact local expiry time and time zone. Absolute `--until` can come later.
- Split on commas, trim surrounding whitespace, reject empty items and option-like destinations, then resolve and deduplicate by enrolled target ID. Quote the argument if it contains spaces.
- Accept inventory/SSH aliases and explicit `user@host`. Resolve with the same `ssh -G` mechanism as `authorize`, matching the enrolled hostname, account and port. Use an alias for nonstandard ports in the first version. Reject ambiguous matches.
- Validate **every** target before Touch ID. Unknown or unenrolled targets fail the whole request with an actionable error; a typo never silently reduces or broadens the grant.
- All selected targets share the certificate's deadline and permissions. One grant is active at a time. A new request while one is active returns `access_already_active` and its details without replacing it or prompting. Reuse it when suitable; replacement requires stopping it and a fresh approval.
- Commands are unrestricted within the selected accounts unless `--force-command` is supplied. A dedicated account with limited privileges is recommended, but existing accounts can be selected. Display the accounts being authorized.
- Default permissions are `clear`: no PTY, port/agent/X11 forwarding or user RC. `--allow-pty` explicitly enables PTY. Scoped forwarding and per-target permission overrides can come later.

## Dedicated help section

Main help has a separate **Temporary access** section, alongside Getting started, Day to day and New Mac and recovery.

```text
Temporary access
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
```

`access help` and `access --help` show detailed examples, one-time `authorize --temporary-access` enrollment, inventory records, generated alias/config paths, cleanup behavior and expiry limitations. Main help also points AI agents to `instructions`.

## Discovery and interaction for AI agents

The installed CLI provides **`touchid-ssh-agent instructions`**, returning concise Markdown with the workflow, examples and boundaries. Main help points to it. Instructions ship in the executable, requiring no repository checkout, account, MCP service or agent-specific plugin.

Maintain the same guidance in [AI agent instructions](ai-agents.md), including a short block users can place in `AGENTS.md`, `CLAUDE.md` or equivalent instructions. The CLI prints that block with `instructions --snippet` and adds it to a file, after asking, with `instructions --add-to FILE`. Those files help discovery; installed CLI instructions describe the available version.

The AI workflow is:

1. Read `instructions`, then inspect `access status --json` without prompting.
2. Reuse a valid grant when its targets, permissions and remaining time cover the task.
3. Otherwise request the smallest useful set and duration: `access app-server,worker-server --for 2h --json`. Native Touch ID is the approval step; the AI cannot approve it.
4. Wait for success, then use exactly the returned SSH configuration and dated per-target aliases/argv. Do not replace the returned config path with the main SSH config.
5. On denial, timeout, expiry or a missing prerequisite, explain the error. Never loop prompts, silently extend access or fall back to the main identity.

`access ... --json`, `access status --json`, `access stop --json` and `access cleanup --json` each write **one JSON document to stdout**. Progress and the human approval summary go to stderr. No ANSI styling or partial JSON on stdout. Every response has `schema_version`, `ok` and `status`; errors add stable `error.code` and actionable `error.message` and exit nonzero. An inactive status query is a successful query. Active results include a grant ID, UTC expiry, remaining seconds, canonical targets, permissions, absolute generated config path and per-target SSH argv. Cleanup reports removed and skipped grant IDs, with a reason for each skip. Return argv arrays instead of shell strings.

Success response (keys sorted as printed; real paths are absolute; `access status --json` also lists `stale_grants`):

```json
{
  "expires_at" : "2026-10-16T00:00:00Z",
  "expires_at_local" : "2026-10-15 21:00:00 -0300 (America/Sao_Paulo)",
  "grant_id" : "20261015-a1b2c3d4e5f6",
  "issued_at" : "2026-10-15T22:00:00Z",
  "ok" : true,
  "permissions" : {
    "force_command" : null,
    "forwarding" : false,
    "pty" : false
  },
  "remaining_seconds" : 7200,
  "schema_version" : 1,
  "serial" : 17,
  "ssh_config_path" : "/example/home/.touchid-ssh-agent/access/grants/20261015-a1b2c3d4e5f6/ssh_config",
  "status" : "active",
  "targets" : [
    {
      "hostname" : "server.example",
      "inventory_alias" : "app-server",
      "port" : 22,
      "requested" : "app-server",
      "ssh_alias" : "app-server-access-20261015-a1b2c3d4e5f6",
      "ssh_argv" : ["ssh", "-F", "/example/home/.touchid-ssh-agent/access/grants/20261015-a1b2c3d4e5f6/ssh_config", "app-server-access-20261015-a1b2c3d4e5f6"],
      "user" : "agent"
    }
  ]
}
```

Status verifies the process and deadline; a leftover metadata file never proves a grant is active. Generated aliases are local handles; server-side principals enforce scope.

## Architecture: short-lived SSH certificates

A **CA** lives in the Secure Enclave, protected by Touch ID like the login key. One approval signs **one certificate containing the selected targets' principals**, with a common deadline and permissions.

```text
person or AI: access app-server,worker-server --for 2h
       │ resolve targets; display accounts, permissions and expiry
       ▼
one-shot launchd job local.touchid-ssh-agent.access.<dir-hash>.<grant-id>
       │ generates an Ed25519 key in its own memory
       │ builds the certificate from the frozen, validated request
       │ CA signs → one Touch ID
       │ publishes, in its access/grants/<grant-id>/ directory:
       │ agent.sock, key.pub, key-cert.pub, ssh_config and known_hosts
       ▼
CLI: authentication-only ssh -N check on every target → confirm (or withdraw)
       ▼
AI: ssh -F <returned-config> app-server-access-<date>-<id> <command>
       │ repeated signatures use the temporary key without Touch ID
       ▼
deadline or access stop
       │ job stops serving and exits; removes public files and socket
       └ servers reject new authentication with an expired certificate
```

| Decision | Choice | Reason |
| --- | --- | --- |
| Process | Separate, short-lived launchd job; no extension to `agent.sock` | Login remains independent. The CA is never offered on any agent socket. |
| Temporary key | Ed25519 in software, in job memory (CryptoKit `Curve25519.Signing`) | No intentional private-key file; supports locked-screen use. Existing `WhenUnlocked` Secure Enclave keys fail while locked, observed in Phase 1. |
| CA | Separate Secure Enclave identity, `current-set` | Separate issuance and login roles; preserve existing login paths and formats. |
| Issuance | The job builds and signs one immutable request | Resolve, display and sign identical target IDs, permissions and deadline; no mutable scope re-read after approval. |
| Failure | `KeepAlive` off; no persisted temporary private key | Crash or logout ends availability. Restart requires another approval. |
| Lifetime | Maximum 12 h; `valid_after` = now minus 5 min | Server-enforced deadline with a small clock-skew margin. |
| Local expiry | Check before every signature, plus a timer and after wake | Unlinking a socket does not invalidate already connected clients; delayed cleanup cannot authorize expired signing. |
| Readiness | Success only after job/config readiness and a temporary-key authentication check on every selected target | Return a usable route or an error; another identity cannot pass the check. |
| Idle sleep | Hold an idle-sleep assertion for the grant, allowing screen lock | Unattended work must not depend on another tool preventing sleep. This does not override lid closure, forced sleep or loss of power. |

`caffeinate -i` or an equivalent power-management assertion prevents idle sleep; `caffeinate -s` alone only applies on AC power. Sleep/resume never extends the deadline.

## One-time enrollment and server-enforced scope

Reuse the existing setup flow with an opt-in:

```bash
touchid-ssh-agent authorize agent@server.example --temporary-access
```

This adds CA trust to the existing login/emergency-key setup and records it in inventory. On an existing target, add missing trust without duplicating keys. Normal `authorize` behavior stays compatible. A grant request never silently modifies a server.

`AuthorizedKey` gained an options field for this line. `RemoteKeys.installScript` still detects presence by public-key blob alone, so enrollment and `audit` read `authorized_keys` back and validate `cert-authority`, the exact principal and restrictions, including duplicate or broader trust lines; existing lines are never edited. Unsupported server authentication policies are detected by a real certificate login during enrollment and readiness, and reported with an actionable failure.

Each enrolled server/account receives a stable, unique, opaque target ID and matching principal, such as `access-<target-id>`. Record the resolved hostname, account, port, trusted host keys, principal and CA fingerprint. New inventory fields remain optional for compatibility.

## Inventory records

CA trust is durable server state and must be recorded per target in an optional `temporaryAccess` object in `inventory.json`, included in the existing encrypted backup. Store:

| Field | Purpose |
| --- | --- |
| `targetId`, `principal` | Identify the enrolled server/account and exact accepted scope. |
| `caPublicKey`, `caFingerprint`, `authorizedKeyOptions` | Identify the installed public CA and restrictions for audit, exact removal and rotation/recovery. |
| `enrolledAt`, `lastAudit`, `lastAuditResult` | Distinguish recorded enrollment from the last observed server state. |
| `lastGrant` (optional) | Retain only the latest grant's ID, certificate serial, temporary public-key fingerprint, generated alias, issue/expiry times, permissions and end time/reason. |
| `caRotation` (optional while pending) | Persist recovery ID, old/new CA public identities, unchanged target scope, and the last verified migration step until old trust removal is confirmed. |

Older inventories without this object remain readable and mean temporary access is not enrolled. Update local inventory and its backup after enrollment, rotation and deauthorization, using the existing backup policy. Record successful grants and their ending; do not let an unbounded grant history grow inside each inventory entry.

Merge inventory changes under a shared write lock with authorize/audit/recover. A background expiry or cleanup callback must not replace newer server/enrollment changes using an old inventory snapshot.

`inventory` shows whether temporary access is enrolled, the CA fingerprint, the latest audit result and latest grant summary. Current activity is checked against the local process/deadline; a recorded `lastGrant` never proves a live grant exists. Recovery restores durable trust, not an active session.

Do not store CA private material, a temporary private key or live socket/config paths in the portable inventory. Current paths and process identity belong in the local grant manifest. Keep the normal server alias separate from generated temporary aliases; a new grant must not rename or replace the permanent inventory entry.

## Scoped trust on the server

That account trusts the CA only for its target principal:

```text
cert-authority,principals="access-example-target",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ecdsa-sha2-nistp256 AAAA... touchid-ca@mac
```

- Never install a generic shared `overnight` principal or unrestricted CA trust. The grant must fail on an unselected enrolled target.
- User certificates have no destination-host allow-list. Target scope depends on the server's principal policy, not local aliases. A server administrator copying or broadening its trust policy is outside the client's guarantee.
- Include each selected target's principal once in **one certificate**, retaining one Touch ID for multiple targets.
- Verify host keys against enrolled trust during setup and readiness checks. Unknown or changed host keys are not silently accepted during a request.
- Certificate and CA-line restrictions combine. The line leaves PTY configurable but denies forwarding and user RC in the first version.
- An optional `source-address` certificate restriction limits client source addresses, not destination hosts.
- Root and `sshd_config` edits are unnecessary when the user can edit that account's `authorized_keys`. Administrators may use `TrustedUserCAKeys` plus appropriately scoped `AuthorizedPrincipalsFile` instead.

## Connection configuration

Generate a config specific to the grant with explicit target connection settings and only the temporary identity. Each target receives an alias in the form `<server>-access-<YYYYMMDD>-<id>`, for example `app-server-access-20261015-a1b2c3d4e5f6`. The date uses the Mac's local time; expiry in machine-readable results remains UTC. Sanitize labels to literal SSH alias characters, bound their length and resolve collisions before publishing. Aliases and grant paths must not be reused to redirect old commands to another grant.

The first version leaves `~/.ssh/config` intact. Store each grant in its own private directory, so there are no accumulated temporary `Host` blocks in the user's config:

```text
~/.touchid-ssh-agent/access/grants/20261015-a1b2c3d4e5f6/
  manifest.json      ownership: grant, data directory, aliases, job identity
  request.json       the frozen request (its SHA-256 is passed to the job)
  job.plist          launchd job definition
  control.sock       CLI ↔ job control channel
  agent.sock         the temporary agent
  key.pub            temporary public key
  key-cert.pub       certificate
  ssh_config         generated config
  known_hosts        host keys pinned from the inventory
```

The manifest identifies the grant, target-to-alias mapping, expected generated files, process identity, issue time and expiry. Validate Unix socket path length before approval. The private key remains only in memory.

Each target's block (real paths are absolute, quoted when they hold spaces):

```sshconfig
Host app-server-access-20261015-a1b2c3d4e5f6
  HostName server.example
  User agent
  Port 22
  HostKeyAlias app-server-access-20261015-a1b2c3d4e5f6
  UserKnownHostsFile /…/access/grants/20261015-a1b2c3d4e5f6/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  UpdateHostKeys no
  CheckHostIP no
  IdentityAgent /…/access/grants/20261015-a1b2c3d4e5f6/agent.sock
  IdentityFile /…/access/grants/20261015-a1b2c3d4e5f6/key.pub
  CertificateFile /…/access/grants/20261015-a1b2c3d4e5f6/key-cert.pub
  IdentitiesOnly yes
  PreferredAuthentications publickey
  PubkeyAuthentication yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  HostbasedAuthentication no
  BatchMode yes
  ForwardAgent no
  ForwardX11 no
  ClearAllForwardings yes
  PermitLocalCommand no
  ControlMaster no
  ControlPath none
  ControlPersist no
  ProxyCommand none
  ProxyJump none
  RequestTTY no
  ConnectTimeout 15
```

`RequestTTY no` is left out when the grant allows a PTY. After the target blocks, a `Host * !<alias>…` block gives every other name `ProxyCommand /usr/bin/false`, `IdentityAgent none` and no authentication methods, so a mistyped name fails without a network connection or credentials.

The returned command is `ssh -F <absolute-config-path> app-server-access-20261015-a1b2c3d4e5f6`, with a remote command appended as needed. The alias selects the target, temporary key and certificate together; it is not itself a private key. The AI receives the full argv rather than having to construct it. Setting only `SSH_AUTH_SOCK` is insufficient: an existing `IdentityAgent` overrides it.

Keep `-F` in every returned command. After cleanup, an old command points to a missing file and fails; it must not fall through to the personal config, DNS resolution of a generated alias or another identity. A future opt-in single managed `Include` could enable plain `ssh ALIAS`, but requires separate tests for inherited `Host *` identities, scope and expired-alias behavior. It is not required for the initial AI workflow.

Resolve required transport settings without importing additional authentication identities, and reject unsupported configurations before approval. This version rejects jump hosts and proxy commands; a later version could support a jump host that is itself selected and enrolled. Verify effective configuration with `ssh -G` and actual certificate authentication with `ssh -v`.

Readiness checks authenticate without opening a shell, command or subsystem (for example, an observed `ssh -N -T` connection closed after authentication). Checking a grant with `--force-command` must never execute its task as a side effect.

Disabling sharing limits accidental reuse after expiry. It cannot close existing connections or prevent a same-user process from deliberately creating a master connection.

## Cleanup without growing the user's config

- Normal expiry, `access stop` and failed/cancelled starts close local signing access and remove that grant's generated config, public key, certificate, socket and manifest. Persistent CA trust, permanent SSH config and inventory entries stay available.
- Before creating another grant, sweep stale directories left by crashes. `access cleanup [--json]` performs the same operation explicitly without Touch ID. `access status` remains read-only and may report stale artifacts with this suggested command.
- Remove only files created by this feature under its owned grant root, identified by a validated manifest. Reject symlink/path escapes and unexpected entries rather than deleting arbitrary directory contents or matching aliases by name alone.
- Serialize cleanup with grant creation/stop. Keep a live, unexpired grant; verify job/process identity rather than a PID alone. If liveness or ownership is uncertain, skip the directory and report why. Expired local jobs must stop before their artifacts are removed.
- When cleanup finds a stale latest-grant record, reconcile its end reason without changing CA enrollment or adding historical records indefinitely. Cleanup is not server-side revocation and does not kill authenticated remote connections.

## Approval, lifecycle and security boundaries

- Display targets/accounts, duration, exact expiry, unrestricted or forced commands and PTY permission before Touch ID. In JSON mode this summary goes to stderr.
- A short dialog reason identifies temporary access, target count and duration, for example `allow temporary SSH access to 2 targets for 2 hours`. Do not claim a truncated dialog shows the complete target list.
- Retain directory `0700`, socket `0600` and peer UID checks. Any process of this user reaching the socket may use the grant; requester process names are informational.
- Denial, timeout, cancellation, failed readiness or abandoned startup must leave no usable partial grant. Publish the socket only after approval; clean up failed starts. A cancelled caller must not leave a newly issued grant running without delivering its result.
- `access stop` closes local clients, exits the job and removes generated files, without Touch ID. Status/stop never authorize issuance.
- Stop and expiry do not kill authenticated SSH connections or remote processes. The software key may be extractable from a compromised process; stopping cannot destroy an attacker's copy. Its certificate remains constrained by server checks until expiry or server-side revocation.
- Account permissions determine what the AI can do. An unrestricted shell may create persistent access, such as another authorized key, even without `sudo`. Temporary authentication is not a sandbox or rollback.
- Validity relies on server clocks; the five-minute margin does not address a badly wrong clock.
- This covers SSH authentication, including compatible Git-over-SSH use. It does not suppress Git commit-signing, `sudo` or unrelated prompts.

## Certificate encoding

Use the deployed OpenSSH type `ssh-ed25519-cert-v01@openssh.com`. Fields in order:

1. 32-byte random nonce and Ed25519 public key.
2. `serial` (`uint64`), from an atomically updated, locked counter in `ca.serial`.
3. Type 1 (user); key ID `access-YYYYMMDD-HHMM-<serial>`.
4. Nonempty, deduplicated enrolled principals.
5. Finite `valid_after` and `valid_before` (`uint64`).
6. Critical options, extensions, empty reserved field and CA public key.
7. CA signature covering every preceding certificate field, including the initial key-type string and CA key field, using the existing P-256 SSH encoding.

Critical options/extensions are lexicographically ordered without duplicate names. Values for `force-command` and `source-address` contain nested SSH strings; permit flags have empty data. Start with no permit extensions; add only `permit-pty` when requested.

The temporary socket offers the key and certificate, never the CA. Either public blob may identify a sign request; both use the same temporary Ed25519 key and return a plain `ssh-ed25519` signature blob. Servers trust the certificate, not the bare temporary key.

Use `ssh-keygen -Lf` to check fields and real `sshd` logins to establish signature validity and authentication. Decoding alone does not prove either.

## Audit, revocation and recovery

- Local logs record issuance, expiry/stop, serial, key ID and each signing request's time and requester chain. No payloads, hosts or remote account names. Signing logs do not prove completed logins or record every remote command.
- Server VERBOSE logs identify the certificate key ID, serial and CA fingerprint.
- `audit` checks CA trust/principal scope as well as login/emergency keys. `deauthorize` removes recorded CA trust too.
- `recover` replaces the old Mac's CA trust as well as its login key, following the per-target sequence below. Old temporary grants and aliases are never restored from backup.
- Removing a CA trust line blocks new authentication through that line; other trust paths may still accept it. Existing connections continue. Administrative KRL revocation can reject a specific serial on new authentication.
- Fingerprint changes may invalidate the CA (`ca_unusable`). Replace it explicitly: move `ca.se` and `ca.pub` aside, then `authorize HOST --temporary-access` creates a new CA and, on each enrolled server, installs and verifies it before removing the previous one by its recorded key.
- README, SECURITY.md and CONTRIBUTING.md distinguish the login-key and CA guarantees from the explicitly approved temporary software key.

### Required recovery sequence for CA trust

This is part of Phase 2 acceptance, not an optional cleanup after recovery. `recover` performs these steps; the Docker tests exercise them, including a server that refuses the new CA and a retry after an interrupted run.

1. **Read the old trust from the kit-decrypted inventory.** Identify the old CA by its recorded public key and fingerprint on each enrolled target. Its private key is not needed for removal and cannot be restored onto the new Mac. Targets without temporary-access enrollment keep their existing recovery behavior; do not enroll them implicitly.
2. **Prepare the new Mac once.** Create a new Secure Enclave CA when needed. Reuse that CA on a resumed recovery rather than creating another identity on every run. Retain the existing emergency-key Keep/Replace choice; `--keep-emergency-key` never means keeping the lost Mac's CA.
3. **Record migration intent before changing a target.** Persist the old and new CA public identities, exact principal/restrictions and progress in a recovery journal/`caRotation` record. Preserve the pre-recovery encrypted backup under the existing recovery safeguards. Progress must survive interruption without forgetting which old CA still needs removal.
4. **Add and verify replacement access on each reachable target.** Authenticate with the kit, verify the server host key and add the new login/emergency keys plus the new CA line with the same target principal and restrictions. Verify the new login as today. Also verify certificate authentication through the new CA using a short-lived internal validation certificate and an authentication-only connection; checking that a public line exists is insufficient. Describe this CA issuance and its Touch ID approval in the recovery flow. The validation key stays in memory and does not become a normal published access grant.
5. **Remove the old credentials once the new login works.** After the new Touch ID login is verified on that target, remove the retired login/emergency keys as appropriate and **every** CA of the lost Mac the inventory recorded (its enrolled CA and, if it left a replacement unfinished, that replacement's CAs), matching their exact public keys/fingerprints. Protect every current new key and preserve unrelated entries. Verify the old CAs are absent from the managed trust location. If an additional unmanaged trust path may accept the old CA, report that revocation is incomplete rather than claiming it is gone everywhere.
   *Changed during the final review:* the original design kept every old credential until the new CA was also verified. The lost Mac's CA cannot help the new Mac (its private key is on the lost Mac), so keeping it protected nothing, while a single failed certificate check (a server refusing certificates, a clock more than five minutes off, a denied prompt) would have kept the lost Mac's login key on that server. The new CA's verification no longer holds back any old credential.
6. **Commit and audit the target, right away.** Save the target's inventory record as soon as it is done (not at the end of the run): this Mac's CA, the retired CAs and the audit result, with completed rotation progress cleared. When the new CA's certificate login failed, record the enrollment as not confirmed (`verified: false`); `access` refuses it until `authorize --temporary-access` confirms it. Retain the existing encrypted-backup policy for full versus partial recovery, and keep a dated copy of the backup the kit opens before any change. Audit the new CA scope and old CA absence in addition to the existing login/emergency checks.

Failure and retry rules:

- If the new login cannot be verified, retain all old trust on that target and report it as pending. If deletion or its verification fails, keep the identities in migration progress and report recovery as incomplete. Do not report that every host revoked the old CA when a host was unreachable or could not be checked.
- A target is skipped on retry only when its login and emergency fingerprints already match this Mac **and** this Mac's CA is recorded with every old CA retired. A target whose record shows an interrupted run (this Mac's key already installed) is finished through the new Touch ID key when the kit no longer opens it; matching fingerprints alone never skip unfinished CA work.
- A retry must preserve valid access and finish pending removal without duplicating trust lines. Missing metadata or uncertain ownership must not lead to guessing and deleting unrelated CAs.
- `recovery test` remains read-only: check the emergency login and report whether recorded CA trust/principal/restrictions are present. It must not create/rotate CAs, issue a new grant or remove trust.
- Update the emergency kit's manual instructions to identify the old CA using the decrypted inventory and explain its removal, alongside the lost login key. Do not require possession of the old CA private key.
- Removing old CA trust rejects future authentication with its still-unexpired certificates through that trust path. Already authenticated connections may continue. The old Mac's local socket/config files cannot be erased remotely; server-side trust removal is what retires its credentials.

## Implementation and acceptance

| Step | Deliverable | Exit criterion |
| --- | --- | --- |
| E1 | Named CA, optional inventory enrollment/latest-grant fields and backup, `authorize --temporary-access`, audit/deauthorize/recover integration | Existing keys/files still work; durable CA trust is recorded; target principals differ; CA never appears on a socket. |
| E2 | Certificate builder, Ed25519 agent identity and P-256 CA signing | OpenSSH decodes and authenticates certificates; vectors cover integers, bounds, ordering, nesting and signature coverage. |
| E3 | Isolated `access` job, grant directories and automatic/manual cleanup | One approval issues a multi-target certificate; no silent extension/restart/persisted private key; expiry applies to connected clients; stale cleanup preserves live grants and user files. |
| E4 | Direct-host CLI, dated aliases/config, JSON contract, dedicated help section and `instructions` | An AI uses returned argv without guessing paths; personal SSH config stays intact; missing enrollment, unknown targets and denial produce stable errors. |
| E5 | Real-server/interactive validation and release documentation | Cases below pass; main-key Touch ID remains unchanged; documentation accurately limits expiry/stop guarantees. |

Required cases:

- One host and comma-separated hosts; whitespace, empty items, duplicates, ambiguous aliases and nonstandard-port aliases. All resolve before approval; one unknown target cannot create a partial grant.
- One Touch ID for multiple selected targets; denial, timeout or abandoned/failed startup publishes no usable grant.
- Repeated commands use returned argv without further Touch ID. Other identities and existing master connections cannot satisfy readiness checks.
- Selected targets accept the certificate; an unselected target with the same CA but a different principal rejects it. Wrong principals, bare keys, expired/malformed certificates are rejected.
- `force-command` wins when supplied. Default extensions deny PTY/forwarding; `--allow-pty` enables only PTY.
- New authentication fails after expiry. Existing connections survive, including new commands via an explicitly created master: document these semantics.
- Stop, crash, logout, sleep/wake, delayed timer delivery, wall-clock changes and connected clients cannot obtain another local signature after expiry.
- JSON remains parseable and schema-consistent; instructions match the CLI; denial never causes an automatic prompt loop.
- Audit/recovery detect and rotate CA trust without changing unrelated keys or broadening scope; old-CA absence is required for completed recovery on each enrolled target.
- Recovery tests start with a still-valid old certificate: after verified replacement and old-CA removal it fails fresh authentication, while a new-CA certificate and replacement login/emergency keys work. Existing connections may survive as documented.
- Recovery interruption after new-key installation, new-CA verification or partial old-CA removal resumes safely. Login/emergency fingerprint matches alone never skip unfinished CA work; offline targets remain explicitly pending.
- Read-only `recovery test`, old inventories without CA fields, `--keep-emergency-key`, duplicate old trust lines and a failed new-CA certificate check have dedicated cases. No active grants or temporary aliases are restored on the new Mac.
- Inventory round-trips optional CA metadata and the bounded latest-grant summary; older files still load and encrypted backups preserve durable trust without restoring live grants.
- Dated aliases are unique literal names, map to the right account/key/certificate, and do not replace permanent aliases. Returned `-F` commands cannot reconnect via a new grant or fallback identity after cleanup.
- Expiry/stop/startup sweep/manual cleanup leave personal config and user files unchanged, preserve live valid grants, handle unknown ownership conservatively and clean only manifested generated files.
- Main help includes a separate Temporary access section; detailed help and installed AI instructions explain inventory, aliases, `-F`, cleanup and the limits of stop/expiry.

### Feasibility evidence

The 2026-10-15 review used an OpenSSH 10.2p1 client and two disposable OpenSSH 10.0p2 servers. Tests confirmed P-256 CA/Ed25519 certificate interoperability, shared-principal access across servers, target-specific principal rejection, forced commands, expiry rejection of fresh authentication, and continued work on existing/master connections. These software test CA keys do **not** establish real Secure Enclave CA issuance or locked-screen operation of the future job.

A subsequent probe uses an actual Secure Enclave P-256 CA, the production SSH codec/agent protocol, a memory-only Ed25519 key and three disposable servers. It verifies the transition from two authorized keys to scoped CA trust and repeated certificate authentication. Its CA deliberately has no biometric requirement; it does not validate the real Touch ID dialog or the job lifecycle. See the [validation report](phase-2-validation.md) for the exact coverage. The implemented feature, including real Touch ID issuance under launchd, is validated as described in the [implementation record](phase-2-implementation.md).

## Implementation notes

Details settled by the implementation:

- **Jump hosts are not supported yet.** A target whose effective ssh configuration uses `ProxyJump` or `ProxyCommand` fails with `unsupported_configuration` in both `authorize --temporary-access` and `access`. Transport settings copied into the grant config are limited to `AddressFamily`, `ConnectTimeout` (15 s when unset), `ServerAliveInterval`, `ServerAliveCountMax` and `TCPKeepAlive`.
- **Enrollment verifies a real certificate login.** After installing the CA line, `authorize --temporary-access` signs a validation certificate (one more Touch ID; `force-command true`, ten minutes, memory-only key) and authenticates with `ssh -N`. A server that rejects it is recorded with `verified: false`, and `access` refuses it until a later `authorize` succeeds. Host keys must already be in `known_hosts`, because the grant config pins them.
- **A previous CA is replaced by `authorize` too.** When an entry recorded another CA (for example after `ca.se` was replaced because changed fingerprints invalidated it), `authorize --temporary-access` records a `caRotation`, installs and verifies this Mac's CA, then removes the recorded old CA through the user's usual access.
- **Names.** Grant IDs are the local date plus 12 random hex digits; aliases are the inventory alias lowercased, reduced to `[a-z0-9._-]` and at most 32 characters, then `-access-<grant-id>` (with `-2`, `-3`… on collisions). Principals are `access-` plus 16 random hex digits. Certificate key IDs use UTC: `access-YYYYMMDD-HHMM-<serial>`.
- **Grant files.** `access/grants/<grant-id>/` holds `manifest.json`, `request.json`, `job.plist` (launchd only), `control.sock`, `agent.sock`, `key.pub`, `key-cert.pub`, `ssh_config` and `known_hosts`. The control socket carries newline-delimited JSON between the CLI and the job (attach, issued, confirm, status, stop). The data directory must be short enough for these socket paths (104 bytes); `access` checks before approval.
- **launchd.** Each grant has its own label, `local.touchid-ssh-agent.access.<data-directory hash>.<grant-id>`, with `RunAtLoad`, `LaunchOnlyOnce`, no `KeepAlive`, `ProcessType Interactive`. The job never unloads itself (launchd would signal it mid-teardown); `access stop`, `access cleanup` and the next request unload finished jobs. The automated tests start the job as a detached process instead (`TOUCHID_SSH_AGENT_ACCESS_LAUNCH=process`), except one launchd test.
- **Readiness** runs `ssh -F <grant config> -v -N -T <alias>` for every target in parallel and requires both `Server accepts key: … ED25519-CERT <temporary key fingerprint>` and `Authenticated to`, then closes the connection.
- **Agent instructions.** Besides `instructions`, the CLI ships the short discovery block (`instructions --snippet`) and can add it to an agent's instructions file between markers, after asking (`instructions --add-to FILE`); a test keeps it identical to the block in the [AI guide](ai-agents.md).
- **Recovery saves each server at once.** `recover` writes a server's record as soon as it is done, keeps a dated copy of the backup the kit opens before changing anything, and finishes a server left by an interrupted run through the new Touch ID key. The tests interrupt a real run with the test-only `TOUCHID_SSH_AGENT_TEST_INTERRUPT=after-removal:<alias>`, which exits right after that server's old keys are removed.
- **Versions.** The feature ships in 0.2.0.
- **What the temporary agent signs.** Only `SSH_MSG_USERAUTH_REQUEST` payloads (`publickey` or `publickey-hostbound`) that offer the grant's key or certificate, for one of the selected accounts. Git signatures and arbitrary data are refused.
- **Deadline.** The job keeps a monotonic deadline (`CLOCK_MONOTONIC`, which keeps counting during sleep) next to the wall-clock one and refuses to sign when either passed; a 2-second wall-clock timer and IOKit wake notifications trigger teardown.
- **JSON.** `status` is `active`, `inactive`, `pending`, `stopped`, `cleaned` or `error`. Error codes: `invalid_arguments` and `invalid_duration` (exit 2); `unknown_target`, `not_enrolled`, `ambiguous_target`, `ca_mismatch`, `rotation_pending`, `host_key_missing`, `unsupported_configuration`, `socket_path_too_long`, `access_already_active`, `access_busy`, `approval_denied`, `approval_timeout`, `approval_unavailable`, `ca_unusable`, `cancelled`, `stopped`, `readiness_failed`, `job_failed`, `stop_failed`, `internal_error` (exit 1).
- **Inventory.** `temporaryAccess` holds `targetId`, `principal`, `caPublicKey`, `caFingerprint`, `authorizedKeyOptions`, `enrolledAt`, `verified`, `lastAudit`, `lastAuditResult`, `lastGrant`, `caRotation` and `retiredCAFingerprints`. `caRotation.step` is `planned`, `replacement-added`, `replacement-verified` (the new login works) or `retirement-started`; `caRotation.extraOldCAs` lists more old CAs when one replacement was itself interrupted. The grant job writes `lastGrant` when the grant becomes active and its end reason (`expired`, `stopped`) when it ends; cleanup marks grants that vanished as `abandoned`. Grant records change only the local inventory; the encrypted backup is rewritten on enrollment, audit, recovery and deauthorization as before.

## Later options

Multiple grants, absolute `--until`, per-target permissions and scoped forwarding can follow demonstrated need. A temporary Secure Enclave key with `AfterFirstUnlockThisDeviceOnly` remains a separate experiment, not a prerequisite. Hard termination of remote sessions requires a separate server-side design.

## References

- [OpenSSH authorized keys, principals and restrictions](https://man.openbsd.org/sshd.8)
- [OpenSSH identity selection and connection sharing](https://man.openbsd.org/ssh_config.5)
- [OpenSSH certificate creation and inspection](https://man.openbsd.org/ssh-keygen.1)

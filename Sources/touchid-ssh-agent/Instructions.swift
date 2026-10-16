import Foundation
import TouchIDSSHCore

/// `access help` / `access --help`.
let accessHelp = """
\(tool) access: temporary SSH access approved with one Touch ID

Request
  access HOST[,HOST...] --for DURATION [--force-command COMMAND] [--allow-pty] [--json]
      HOST is an inventory name, an ssh alias or user@host of a server enrolled for
      temporary access; separate several with commas. Every host is checked before
      Touch ID: one unknown or unenrolled host fails the whole request. DURATION is
      30m, 2h, 1h30m and so on, at most 12h. One Touch ID approves one certificate for
      all hosts; ssh logins through the returned commands then need no Touch ID until
      the grant ends. One grant is active at a time.
      The selected accounts may run any command, unless --force-command limits every
      login to one command. No PTY unless --allow-pty. Agent, port and X11 forwarding
      and user rc files are always denied.
  access status [--json]   The active grant, its expiry and the exact ssh commands.
                           Never asks for Touch ID and changes nothing.
  access stop [--json]     Ends the grant now and removes its local files.
  access cleanup [--json]  Removes files left by grants that ended abnormally (crash,
                           logout, reboot). Keeps a live grant.

One-time enrollment, per server
  authorize HOST --temporary-access
      With the access you already have, adds this Mac's CA to the account's
      ~/.ssh/authorized_keys as a single line that accepts only that account's own
      principal (principals="access-<id>") and denies forwarding and user rc. It checks
      a certificate login and records the CA trust in the inventory and its encrypted
      backup. The CA lives in the Secure Enclave and needs Touch ID for every
      certificate. `access` never changes a server by itself.

Using a grant
  Each host gets a dated alias, such as web-access-20261015-a1b2c3d4e5f6, defined in the
  grant's own ssh_config:
      ~/.touchid-ssh-agent/access/grants/<grant-id>/ssh_config
  Your ~/.ssh/config is not changed. Use the exact command that access prints (or the
  ssh_argv in --json output), adding the remote command at the end:
      ssh -F ~/.touchid-ssh-agent/access/grants/<grant-id>/ssh_config web-access-... uptime
  That config offers only the grant's key and certificate, checks the host keys recorded
  in the inventory, and disables forwarding and connection sharing.

When a grant ends
  At expiry, or after access stop, the grant job stops signing and removes its socket,
  key, certificate and ssh_config; old commands then fail ("Can't open user config
  file") instead of falling back to other keys. Servers also reject the certificate after
  its expiry by themselves. Expiry and stop only block new logins: sessions and
  commands already running continue, and changes made on the servers stay.
  A crash, logout or reboot ends the grant as well; nothing restarts it. Its leftover
  files go with the next request or access cleanup. Cleanup never touches CA trust or
  the inventory; `deauthorize` removes CA trust from a server.

Inventory
  `inventory`, `status` and `audit` show which servers trust the CA, its fingerprint, the
  last audit and the latest grant. A recorded grant is history, not proof that one is
  active: use access status.

Limits
  Any process of your macOS user can use an active grant, like any SSH key it can read.
  The temporary key is a software key held in the grant job's memory. Jump hosts and
  proxy commands are not supported for temporary access yet.

AI agents: run `\(tool) instructions`.
"""

/// `instructions`: the workflow for AI agents, in Markdown.
let aiInstructions = """
# touchid-ssh-agent: temporary SSH access for AI agents

These instructions ship with touchid-ssh-agent \(version) and describe this version.

## Workflow

1. Check for a grant first; this never asks for Touch ID:
   `touchid-ssh-agent access status --json`
   If `status` is `active` and its `targets`, `permissions` and `remaining_seconds`
   cover your task, use it.
2. Otherwise request the smallest useful set of hosts and the shortest useful duration:
   `touchid-ssh-agent access app-server,worker-server --for 2h --json`
   The user approves with Touch ID on the Mac; you cannot approve it. Wait for the
   command to exit. It prints exactly one JSON document on stdout; progress goes to stderr.
3. On success (`"ok": true`, `"status": "active"`), run commands with each target's
   `ssh_argv`, appending the remote command as more argv elements, without a local shell:
   `["ssh", "-F", "/…/access/grants/<grant-id>/ssh_config", "app-server-access-20261015-a1b2c3d4e5f6", "uptime"]`
   Keep the `-F` path and the dated alias exactly as returned. Do not use the main ssh
   config, SSH_AUTH_SOCK, other keys or connection sharing.
4. A nonzero exit with `"ok": false` is a failure. Read `error.code`:
   - `unknown_target`, `not_enrolled`: the host needs a one-time
     `touchid-ssh-agent authorize HOST --temporary-access` by the user. Do not change
     server trust yourself.
   - `approval_denied`, `approval_timeout`, `approval_unavailable`, `cancelled`: report
     it. Do not request again in a loop; ask the user first.
   - `access_already_active`: `active_grant` describes the current grant. Use it if it
     covers the task; otherwise tell the user. Do not stop a grant other work may need.
   - `access_busy`: another request is waiting for approval. Wait, then check status.
   - `invalid_arguments`, `invalid_duration`, `ambiguous_target`, `readiness_failed`,
     `unsupported_configuration`, `host_key_missing`, `ca_mismatch`, `rotation_pending`:
     explain the message to the user and stop.
5. When a grant was only for your task, end it: `touchid-ssh-agent access stop --json`.
6. When a grant expires, logins fail. Report it; never extend access silently.
7. If status lists `stale_grants`, `touchid-ssh-agent access cleanup --json` removes only
   leftover generated files of ended grants.

## Boundaries

- Only the user approves, with Touch ID. Never try to bypass, script or work around it.
- After a denial or expiry, do not fall back to the main login key, the emergency key,
  another agent or an existing connection.
- Expiry and stop block new logins; sessions already open keep running. A grant is not
  a sandbox: the selected accounts' permissions apply and changes are not undone.
- Grants do not cover git commit signing, sudo or any other prompt.
- `inventory` shows enrolled servers and the latest grant; that record is history.
  Only `access status` says whether a grant is active.

## JSON fields

- Every document: `schema_version`, `ok`, `status` (`active`, `inactive`, `pending`,
  `stopped`, `cleaned` or `error`). Errors add `error.code` and `error.message`.
- Active grants: `grant_id`, `issued_at` and `expires_at` (UTC), `expires_at_local`,
  `remaining_seconds`, `serial`, `permissions` (`force_command`, `pty`, `forwarding`),
  `ssh_config_path`, and `targets[]` with `requested`, `inventory_alias`, `hostname`,
  `user`, `port`, `ssh_alias` and `ssh_argv`.
- Status also lists `stale_grants[]`; cleanup lists `removed[]` and `skipped[]`, each with
  `grant_id` (and a `reason` when skipped).
"""

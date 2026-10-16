# Instructions for AI agents: temporary SSH access

> **Implemented.** `touchid-ssh-agent instructions` prints the same guidance for the installed version, and main help points to it. When the two differ, trust the installed instructions.

## Discovery

Read the dedicated **Temporary access** section of `touchid-ssh-agent help`, then `touchid-ssh-agent instructions`. `access help` / `access --help` explain enrollment, inventory, dated aliases and cleanup. Installed guidance describes the available version. No MCP service, agent-specific plugin or repository checkout is required.

## Workflow

1. Inspect `touchid-ssh-agent access status --json`. It never requests Touch ID.
2. Reuse an active grant if its destinations, permissions and remaining time cover the authorized task.
3. Otherwise request the smallest useful target set and duration:

   ```bash
   touchid-ssh-agent access app-server,worker-server --for 2h --json
   ```

   Add `--force-command COMMAND` for a single fixed task and `--allow-pty` only when a terminal is needed. The user approves through native Touch ID. Wait for the command result; an attempted request is not approval.
4. Success includes `expires_at`, `remaining_seconds`, permissions, aliases such as `app-server-access-20261015-a1b2c3d4e5f6` and per-target `ssh_argv`. Append the remote command as an argv element and execute without a local shell. Keep the returned `-F` config path; the alias is defined in that grant's file, not the user's main SSH config. Use the original inventory destination when requesting another grant.
5. A nonzero exit and `error.code` mean failure. Never infer approval from a file, socket, previous grant or progress text. `access_already_active` includes the current grant as `active_grant`; `access_busy` means another request is waiting for approval.
6. On denial or timeout, report the outcome without repeatedly opening Touch ID. On expiry, explain that another approval is needed; do not silently extend access.
7. If an active grant does not cover the task, report the conflict. Do not stop someone else's work or broaden scope automatically.
8. Stop a task-specific grant with `touchid-ssh-agent access stop --json` when appropriate. Do not stop a shared grant still needed by other work.
9. Expiry/stop normally remove generated files. If status reports stale artifacts, `touchid-ssh-agent access cleanup --json` removes only owned stale files and preserves live, valid grants. Do not edit personal SSH config or remove CA trust as a substitute for cleanup.

## Missing enrollment

Each target needs one-time temporary-access enrollment by the user: `touchid-ssh-agent authorize HOST --temporary-access`. Missing enrollment (`not_enrolled`) or an unknown host (`unknown_target`) returns an actionable error before Touch ID. Explain that prerequisite; requesting a grant never modifies server trust.

The inventory records the target's CA trust, principal, fingerprint and audit result, plus a bounded latest-grant summary. This record helps find enrolled destinations; it does not by itself prove a grant is active. Use `access status --json` for live validity and current command paths.

## Boundaries

- Native Touch ID approves issuance. AI software never supplies or bypasses approval.
- Do not switch to the login key, emergency key, another agent or connection sharing to bypass denial or expiry.
- Expiry/stop prevent further local signing; certificate expiry also rejects new authentication. Existing SSH connections and remote processes may continue.
- Selected account permissions apply. A grant is not a sandbox and does not roll back changes.
- This feature does not approve Git commit signatures, `sudo` or unrelated prompts.
- Servers behind jump hosts or proxy commands are not supported yet (`unsupported_configuration`).

## Copyable discovery block

Users can place this in `AGENTS.md`, `CLAUDE.md` or equivalent instructions. The installed CLI prints the same block with `touchid-ssh-agent instructions --snippet`, and adds it to a file (or updates the copy it added before) with `touchid-ssh-agent instructions --add-to FILE`, after showing it and asking for confirmation. For example `~/.claude/CLAUDE.md` for Claude Code, or `~/.codex/AGENTS.md` for Codex.

```markdown
## SSH access to servers (touchid-ssh-agent)

To run commands on a server over SSH, use temporary access from touchid-ssh-agent.
Run `touchid-ssh-agent instructions` once and follow that workflow: check
`touchid-ssh-agent access status --json` first; when needed, request
`touchid-ssh-agent access HOST[,HOST...] --for DURATION --json` with the fewest
servers and the shortest time that fit the task, and wait while the user approves
with Touch ID. Then use exactly the returned per-target `ssh_argv`, with its `-F`
config and dated alias. Never bypass a denial or expiry, retry the prompt in a
loop, fall back to other keys, or stop a grant you did not request.
```

## Acceptance

An agent given only the discovery block and executable must discover the dedicated help section, request a two-target grant, use returned `-F` argv and dated aliases for repeated SSH commands, and handle missing enrollment, denial, expiry and stale cleanup without guessing paths, editing personal config or falling back to the main identity. Validate JSON stdout separately from human progress on stderr.

The CLI side of this is covered by the Docker tests (JSON documents on stdout, error codes, returned argv, cleanup) and by `make test-touchid` (real approval, denial and timeout). A session with an actual AI agent is not part of the automated tests.

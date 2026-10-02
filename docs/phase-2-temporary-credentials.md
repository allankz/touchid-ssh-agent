# Phase 2: temporary credentials for agents (overnight use)

> Status: **design approved, not implemented**. Prerequisites: Phase 1 validated with real Touch ID (`make test-touchid`) and installed on the Mac.

## Problem

An AI agent or an automation needs SSH during the night, when nobody will touch Touch ID. At the same time, the main key must keep requiring Touch ID on every use, and any overnight access must:

- have a **deadline**, enforced by the server and not by the Mac;
- have a **scope**: a single remote user, preferably a single command, no tunnels;
- be **traceable**: which credential, from which night, made each login;
- end by itself: nobody has to remember to revoke anything in the morning.

## Solution: short-lived SSH certificates

A **CA** (certificate authority) lives in the Secure Enclave, protected by Touch ID like the login key. Before going to bed, a single touch issues an OpenSSH certificate for a throwaway key:

```text
23:00  touchid-ssh-agent overnight start --until 07:00 --principal overnight --force-command /usr/local/bin/nightly-task
         │  the CLI prints every parameter in the terminal
         ▼
       launchd job "local.touchid-ssh-agent.overnight" (its own process)
         │  generates an Ed25519 key in memory only
         │  builds the certificate and asks the CA to sign it → Touch ID (1 touch)
         │  publishes ~/.touchid-ssh-agent/overnight.sock, overnight.pub and overnight-cert.pub
         ▼
night  the AI agent uses IdentityAgent overnight.sock → logs in without Touch ID, within the certificate
         │  every use is logged with the requesting process chain
         ▼
07:00  the job exits and removes the socket and files; the key disappears with the process
       the server already rejects the expired certificate, even if something fails locally
```

The certificate works on every server that trusts the CA. No server needs to be edited at night.

## Decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Where the overnight session runs | A **separate**, short-lived launchd job (`local.touchid-ssh-agent.overnight`) started by `overnight start` | The login agent stays minimal and never loads the CA. No new extension in the `agent.sock` protocol. A bug in the overnight session cannot take down login. Stopping the job ends everything. |
| Overnight key | Ed25519 in **software, in the job's memory only** (CryptoKit `Curve25519.Signing`) | It never touches the disk. A Secure Enclave key with `WhenUnlocked` accessibility **fails while the screen is locked** (`errSecInteractionNotAllowed`, observed during Phase 1 testing), and the screen will be locked at night. |
| Who builds the certificate | The job itself, from the CLI parameters | The Touch ID text describes exactly what will be signed. The CA never has to be offered on any socket, unlike `ssh-keygen -s ... -U`. |
| CA identity | A second Secure Enclave identity (`ca`), separate from the login key, `current-set` policy | Separate roles. The CA **never** appears in `ssh-add -L`, neither on `agent.sock` nor on `overnight.sock`. |
| Job failure at night | Ends the session (fail closed); does **not** restart (`KeepAlive` off) | A new key would require a new Touch ID. Better to lose the night than to issue a credential without approval. Documented so nobody finds out only at 07:00. |
| Duration | At most **12 h**; `valid_after` = now − 5 min (clock skew margin) | Limits the damage of a typo in `--until`. |
| Concurrent sessions | One at a time; no `renew`/`extend` | Extending means stopping and issuing again, with a new Touch ID. |
| Default certificate permissions | `clear`: no PTY, no port/agent/X11 forwarding, no `~/.ssh/rc` | The agent asks only for what it needs (`--allow-pty`, `--allow-port-forwarding`). |

## Setup on each server (once)

Create a dedicated user with minimal permissions and no `sudo`; here it is called `agent`. In that user's `~/.ssh/authorized_keys`, add the CA line, which the CLI prints with `touchid-ssh-agent ca authorized-line`:

```text
cert-authority,principals="overnight",no-agent-forwarding,no-port-forwarding,from="203.0.113.10" ecdsa-sha2-nistp256 AAAA... touchid-ca@mac
```

- **`principals="overnight"`**: the certificate must list the `overnight` principal. Convention: the principal describes the **purpose** (`overnight`) and the Unix user describes the **account** (`agent`). Without `principals=`, `sshd` would require the principal to equal the user name.
- **Options on the line combine with the certificate's**, and the most restrictive wins. That is why `from=` here is a second lock, independent of the certificate.
- It requires neither `root` nor changes to `sshd_config`. Whoever administers the server can use `TrustedUserCAKeys` + `AuthorizedPrincipalsFile` instead.
- **Rotating the CA**: add the new line, test, remove the old one. If the CA becomes unusable (fingerprints changed under the `current-set` policy), the old line stays harmless until it is removed.

## Setup on the AI agent's side

`touchid-ssh-agent config nightly-server --overnight --host server.example --user agent` prints:

```sshconfig
Host nightly-server
  HostName server.example
  User agent
  IdentityAgent ~/.touchid-ssh-agent/overnight.sock
  IdentityFile ~/.touchid-ssh-agent/overnight.pub
  CertificateFile ~/.touchid-ssh-agent/overnight-cert.pub
  IdentitiesOnly yes
  ForwardAgent no
```

It is the same trap as in Phase 1: with `IdentitiesOnly yes`, `ssh` only offers identities it finds in `IdentityFile`/`CertificateFile`. That is why the job writes the public key and the certificate (both public) while the session is active. **Exit criterion**: confirm with `ssh -v` that the certificate is offered and accepted.

The Mac must stay **awake** all night. The screen may lock, but the system must not sleep. The agent's tool usually takes care of this; if it does not, use `caffeinate -s`.

## Touch ID and permissions

- Only your own user can call `overnight start`, because only it can load jobs into the `gui/<uid>` domain. Even so, **Touch ID is what authorizes**. A process that tries to start a session on its own runs into the prompt.
- Before the prompt, the CLI prints every parameter: key ID, serial, principal, validity, forced command, addresses and permissions.
- The dialog shows one short line, for example: `issue a temporary SSH credential "overnight" valid until 07:00`. Keep it to one line so the dialog never truncates it.

## Certificate details (for the implementer)

The format is OpenSSH's `PROTOCOL.certkeys`, type `ssh-ed25519-cert-v01@openssh.com`:

- Fields, in this order:
  1. nonce: 32 random bytes;
  2. Ed25519 public key;
  3. `serial` (`uint64`): an increasing counter in `~/.touchid-ssh-agent/ca.serial`;
  4. `type` = 1 (user);
  5. key ID: `overnight-YYYYMMDD-HHMM-<serial>`;
  6. principals;
  7. `valid_after` and `valid_before`;
  8. critical options;
  9. extensions;
  10. reserved (empty);
  11. CA public key.
- The **CA signature** covers everything up to and including the CA key field. It uses the `ecdsa-sha2-nistp256` blob that Phase 1 already produces.
- **Critical options and extensions** are sorted lexicographically by name. The values of `force-command` and `source-address` are `string(string(value))`. Flag extensions (`permit-pty` etc.) have empty data.
- The overnight socket lists both the key and the certificate. Sign requests may arrive with either blob, and both are signed by the Ed25519 key. The signature itself is a plain `ssh-ed25519` blob, even when authentication uses the `-cert-v01` algorithm.
- **Oracle**: `ssh-keygen -Lf overnight-cert.pub` must show every field that was set. Then `sshd` must accept it.

## Audit and revocation

- **On the server**, `sshd` logs every login with the key ID, serial and CA fingerprint: `Accepted publickey for agent ... ED25519-CERT ... ID overnight-20261002-2300-7 (serial 7) CA ECDSA SHA256:...`.
- **On the Mac**, the log records the issuance (key ID, serial, validity) and each use (time, process chain). It records no payload, remote user names or hosts, the same rule as Phase 1.
- **Stopping early**: `touchid-ssh-agent overnight stop` ends the job. The key only existed in memory, so no copy survives.
- **Server-side emergency**: removing the `cert-authority` line invalidates every certificate from the CA. With `root`, a KRL in `RevokedKeys` revokes a specific serial.

## Remaining risks

- During the window, **any process of your user** that can reach `overnight.sock` can log in within the certificate's limits. The defenses are the dedicated user, `force-command`, `from=`/`source-address` and a short window.
- The AI agent can do damage **within** the allowed scope. Designing that scope (what the `agent` user can do, which command is forced) is the most important part of the setup.
- Validity depends on the server's clock. The 5 min margin covers small differences, not badly wrong clocks.

## Alternatives considered

### Pausing Touch ID for a few hours: rejected

Letting the main agent sign without asking during the night unlocks **the main key**: for any process of the user, for any server, with no command limit. And the end of the window would depend only on the Mac. The certificate has a small scope and a deadline enforced by the server.

### Temporary key with `expiry-time` in `authorized_keys`: simple alternative

For a single server, without a CA:

```text
expiry-time="20261002070000",restrict,command="/usr/local/bin/nightly-task" ssh-ed25519 AAAA... nightly
```

The server rejects the key after that time (OpenSSH ≥ 8.2). The downside is editing the server every night and cleaning up expired lines. With several servers or frequent use, the certificate is worth it.

### `ssh-keygen -s ca.pub -U` + `ssh-add -t`: rejected as the final design

It uses only OpenSSH tools, but it requires offering the CA on an agent socket. The temporary key would also touch the disk before `ssh-add`, and overnight use would not be logged with the requester.

## Implementation steps

| Step | Deliverable | Exit criterion |
| --- | --- | --- |
| E1 | Named identities (`login`, `ca`); `ca create`, `ca pubkey`, `ca authorized-line` | The CA never appears in `ssh-add -L` on any socket; Phase 1 still passes |
| E2 | Certificate building and signing | `ssh-keygen -Lf` shows every field; vectors for option ordering and nesting |
| E3 | `overnight` job (socket, public files, expiry, per-use log) and the `overnight start/status/stop` CLI | Expiry and `stop` remove the socket and files; a job failure does not restart |
| E4 | `config --overnight` and usage documentation | `ssh -v` shows the certificate offered and accepted |
| E5 | Tests against the Docker `sshd` with the `cert-authority` line | The cases below |

E5 cases:

- A valid certificate logs in.
- A validity window entirely in the past: rejected.
- Wrong principal: rejected.
- `force-command` wins over the requested command (check the output).
- After `overnight stop`, there is no socket and login fails.
- `agent.sock` is unchanged: the login key still asks for Touch ID.
- The `sshd` VERBOSE log shows the key ID and serial.

## Open questions

1. Which overnight tasks actually exist, and which commands should `force-command` allow: a single script that dispatches tasks, or one certificate per task?
2. A single principal (`overnight`) or one per task type (`overnight-backup`, `overnight-deploy`)?
3. Is it worth evaluating an overnight key in the Secure Enclave with `AfterFirstUnlockThisDeviceOnly` accessibility, so it is not extractable even from process memory, if the Secure Enclave accepts that combination while the screen is locked?

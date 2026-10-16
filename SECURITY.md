# Security Policy

touchid-ssh-agent is experimental software (0.2.x) and has not been independently audited. Keep the emergency key installed on every server you protect with it (`touchid-ssh-agent audit`).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x (latest `main`) | Yes |
| Anything older | No |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Include:

- the commit or version you tested;
- macOS version and Mac model;
- steps to reproduce, and what an attacker gains.

This is a personal project maintained on a best-effort basis. The goals are to acknowledge a report within 7 days, to agree on a disclosure date with the reporter, and to credit reporters who want to be credited.

## Threat model

### What it protects against

- **Copying the private key.** The login key and the temporary-access CA are generated inside the Secure Enclave and never leave it. The files on disk are blobs that only this Mac's Secure Enclave can use.
- **Using the key without the owner present.** Every login-key signature and every certificate the CA issues requires Touch ID. There is no reuse window, no silent mode and no password fallback. Temporary access is the one explicit exception, described next.
- **Temporary access beyond what was approved.** One Touch ID issues one certificate, for the servers and permissions shown, until a deadline of at most 12 hours. Each enrolled server account trusts the CA only for its own principal, so the certificate cannot log in elsewhere; the servers enforce its expiry themselves. The grant's private key exists only in its job's memory, is never written to disk, and is never renewed: a crash, logout or reboot ends the grant.
- **Silent use by local software**, including AI agents. Any process of the user can *request* a signature, but only a fingerprint can *approve* it.
- **Other local users.** The socket is `0600` inside a `0700` directory, and the agent rejects peers whose UID differs from its own.
- **Moving the key to another Mac.** The blob is bound to this device and `WhenUnlockedThisDeviceOnly`.
- **Being locked out when the Mac is gone.** The emergency kit and the encrypted inventory backup let you find and reach your servers from any computer.
- **Reading the server list from the cloud.** `inventory.age` is encrypted with age to the emergency key; the backup folder's README names no server.

### What it does not protect against

Temporary access deliberately trades per-signature Touch ID for unattended work, within the approved scope and deadline:

- **Other processes of your user during an active grant.** Any process running as you can use the grant's socket until it ends, as it could use any SSH key file you can read. The requesting process chain in the log is informational, not a boundary.
- **Extraction of the grant's key.** It is a software Ed25519 key in the grant job's memory. Malware running as you (or as root) could copy it; a copy works until the certificate expires or the server's CA line is removed. Stopping the grant cannot destroy a copy.
- **Ending what already started.** Expiry, `access stop` and removing CA trust block new authentication only. Open sessions, running commands and changes already made continue. A grant is not a sandbox: the selected account's permissions apply, and an unrestricted shell can install other persistent access.
- **Trust configured outside `authorized_keys`.** `audit`, `deauthorize` and `recover` manage the CA line this tool installs in `~/.ssh/authorized_keys`. A server that also trusts the CA elsewhere (for example `TrustedUserCAKeys`) is not checked.
- **Badly wrong server clocks.** Certificates start five minutes early to absorb small differences; a server clock far off can reject a valid certificate or accept one after its deadline.
- **Sleep you did not choose.** A grant prevents idle sleep only; closing the lid, a forced sleep or a power loss stop it.


- **An attacker who controls your user session and gets you to approve.** The prompt describes each request as well as the protocol allows, but you still have to read it.
- **root or kernel compromise** of the Mac.
- **Compromised servers**, or agent forwarding to them. Keep `ForwardAgent` off.
- **Destination checks without `publickey-hostbound`.** For older servers the agent cannot know where a signature will be used. The process chain shown in the prompt is informational and can be stale.
- **Loss of availability.** The Touch ID key is gone if the Mac fails, if fingerprints change under the `current-set` policy, or after `deauthorize --all` deletes it. The emergency kit covers this only if it was stored outside the Mac.
- **Theft of the emergency kit together with its passphrase.** The emergency key is a regular software key: whoever has the kit and the passphrase can log in to every server that trusts it, without Touch ID. Its protection is the passphrase (about 119 bits when generated, bcrypt KDF with 200 rounds) and keeping the kit off the Mac, ideally apart from the passphrase.
- **A man in the middle during recovery** for servers whose host key was never recorded (entries recorded before host keys were stored, until their next `audit`).
- **Reading the local inventory on a stolen Mac.** `inventory.json` is plain JSON (mode `0600`) so the agent can use it without a passphrase. FileVault protects it at rest; `status` warns when FileVault is off.

## Security design

- **Key protection**: CryptoKit `SecureEnclave.P256.Signing.PrivateKey`, accessibility `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, flags `privateKeyUsage` plus `biometryCurrentSet` (default) or `biometryAny`. The Secure Enclave enforces the policy; editing the file or the binary cannot remove it.
- **Authorization**: a fresh `LAContext` for every signature, reuse duration 0, prompt cancelled after 60 s. Sign requests are serialized, so only one prompt is shown at a time. The temporary-access CA uses the same signer, with its own context per certificate.
- **Small protocol surface**: only `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST` are implemented. Everything else (add, remove, lock, extensions) gets `SSH_AGENT_FAILURE`. Messages are capped at 256 KiB, parsed strictly with bounds checks, and malformed input closes the connection.
- **Socket hygiene**: the agent refuses to replace a file that is not a socket or a socket another agent is serving, and removes its socket on exit.
- **Output checks**: every signature is verified against the public key before it is returned.
- **Untrusted text**: user names, namespaces, host names and process names are stripped of control characters and truncated before they reach the prompt or the log.
- **Logs**: time, event, process chain and outcome only. No key material, payloads, remote user names or hosts. Grant events go to `access.log` with the grant ID, certificate serial and key ID.
- **Test-only keys**: keys without Touch ID can only be created through `@_spi(Testing)` API, which refuses the default directory and is not reachable from the CLI.
- **Emergency kit**: `ssh-keygen` generates the key in a new session without a controlling terminal, with the passphrase written to its stdin. The passphrase never appears on a command line or in the environment, and askpass variables are removed. The kit must open with the passphrase (`ssh-keygen -y`) before it is shown to the user. It is erased from the Mac once the user confirms it was saved, and only the public key is kept.
- **Imports**: `recovery import` accepts only ed25519 or rsa public keys and refuses private keys.
- **Inventory backup**: `age -R recovery.pub`, with the plaintext piped through stdin (never written to a temporary file) and the result moved into place atomically. Replacing the emergency key re-encrypts the backup for the new key.
- **recover and recovery test**:
  - The emergency key is loaded into a throwaway `ssh-agent` with `ssh-add -`, with the kit arriving on stdin, so this tool never writes the key to disk. The agent is killed when the command ends.
  - age and ssh-add read the passphrase from the terminal themselves; this program never sees it.
  - Server host keys are checked against the ones recorded in the inventory. Only entries recorded before host keys were stored fall back to trust on first use, with a visible warning; the next `audit` records them.
  - Every server is checked with the emergency key before anything changes, and no server is changed until the user types `RECOVER`.
  - On each server, this Mac's keys are added first. The old keys are removed only after the new Touch ID key has logged in, only when their fingerprint matches the lost Mac's key, or the used emergency key when the user chose to replace it, exactly, and never when they are this Mac's keys.
  - If any server fails, its old keys stay, the cloud backup is not replaced, and the old kit keeps working for another run.
- **deauthorize**: removes only the `authorized_keys` lines holding this Mac's Touch ID key or emergency key, matched by the exact key, keeping the file's inode and permissions. When no other key would be left, nothing is written until the user confirms, because the server would then accept only a password or console access.
- **Temporary access**:
  - *CA*: a separate Secure Enclave key (`ca.se`), always `biometryCurrentSet` and `WhenUnlockedThisDeviceOnly`. It signs only certificates, after Touch ID, and is never offered on any socket. Serial numbers come from a counter updated under a file lock.
  - *Enrollment*: `authorize --temporary-access` appends one line, `cert-authority,principals="access-<id>",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc`, with a stable random principal per server account. Existing lines are never edited; a line holding the CA with broader options is reported and enrollment is refused. A real certificate login is checked before the enrollment is recorded.
  - *Issuance*: every requested server must resolve to exactly one enrolled inventory entry before Touch ID. The CLI writes the request, shows its summary, and passes its SHA-256 to the job, which signs only those exact bytes. The certificate (`ssh-ed25519-cert-v01@openssh.com`) lists only the selected principals, no extensions except `permit-pty` when asked, `force-command` when asked, and `valid_before` at most 12 hours away.
  - *Grant job*: a per-grant launchd job in the GUI session with `RunAtLoad`, `LaunchOnlyOnce`, no `KeepAlive` and its plist inside the grant directory, so nothing restarts it. The command that requested it must stay attached until every server accepted the certificate; if it goes away, the pending prompt is withdrawn and nothing is published.
  - *Temporary agent*: offers only the grant's key and certificate, implements only "list identities" and "sign", signs only SSH login requests for the selected accounts, and checks the deadline against the wall clock and a monotonic clock that keeps running during sleep before every signature, including on connections opened earlier. The socket is `0600` inside a `0700` directory, with the same UID check and size limits as the login agent.
  - *Readiness*: `ssh -N` authenticates without opening a session (so no command, shell or forced command runs) and must show that the server accepted the certificate's key; connection sharing is off.
  - *Generated config*: a separate file per grant that selects only the grant's key and certificate (`IdentitiesOnly`), pins the host keys recorded in the inventory, disables forwarding and connection sharing, and makes any other host name fail without a network connection. Commands always carry `-F`, so they fail once the file is gone.
  - *Cleanup*: only directories whose manifest names them and this data directory, holding only file names this tool creates, owned by the user and without symlinks, are removed, through descriptors opened without following links. A job is recognized by pid and start time; live grants are kept and uncertain cases are skipped with a reason.
  - *Recovery*: the lost Mac's CA is removed only by the exact key recorded in the inventory (whose fingerprint must match), only after this Mac's CA, login and certificate login were verified on that server, and progress is saved before each change so a retry finishes pending CA work.
  - *Sleep*: an idle-sleep assertion for the grant's lifetime, released when it ends; the screen may lock.
- **ssh config edits**: only after the user confirms. New `Host` blocks are appended; when lines are added to an existing block, the previous file is saved next to it as `.touchid-backup` first.
- **authorize and audit**: keys are appended by a small POSIX `sh` script that matches existing keys by blob, fixes a missing final newline and quotes only a restricted character set. The Touch ID check disables connection sharing (`ControlPath=none`), uses `BatchMode`, and confirms from `ssh -v` that the server accepted the Touch ID key's fingerprint, so another configured key cannot pass for it.

## Scope

In scope:

- signing without Touch ID approval, or extracting or using the key without it;
- crashes, hangs or memory-safety issues triggered through the socket;
- access to the agent from another local user;
- sensitive data reaching the log;
- the emergency key, its passphrase or the plaintext inventory left on disk or exposed to other processes;
- a prompt that misdescribes a request beyond the limitations documented here and in the README;
- issuing a temporary grant without Touch ID approval, or one broader than the summary showed (other servers, permissions or a later deadline);
- a temporary agent signing after its deadline, for an account that was not selected, or anything other than an SSH login;
- the CA offered on any socket or usable without Touch ID;
- cleanup or recovery removing files or `authorized_keys` lines this tool does not own.

Out of scope:

- attacks that need root or physical access to an unlocked Mac;
- approving a prompt that correctly described the request;
- the documented limitations above;
- vulnerabilities in macOS or OpenSSH themselves (please report those upstream).

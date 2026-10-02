# Security Policy

touchid-ssh-agent is experimental software (0.1.x) and has not been independently audited. Keep the emergency key installed on every server you protect with it (`touchid-ssh-agent audit`).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (latest `main`) | Yes |
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

- **Copying the private key.** The key is generated inside the Secure Enclave and never leaves it. The file on disk is a blob that only this Mac's Secure Enclave can use.
- **Using the key without the owner present.** Every signature requires Touch ID. There is no reuse window, no silent mode and no password fallback.
- **Silent use by local software**, including AI agents. Any process of the user can *request* a signature, but only a fingerprint can *approve* it.
- **Other local users.** The socket is `0600` inside a `0700` directory, and the agent rejects peers whose UID differs from its own.
- **Moving the key to another Mac.** The blob is bound to this device and `WhenUnlockedThisDeviceOnly`.
- **Being locked out when the Mac is gone.** The emergency kit and the encrypted inventory backup let you find and reach your servers from any computer.
- **Reading the server list from the cloud.** `inventory.age` is encrypted with age to the emergency key; the backup folder's README names no server.

### What it does not protect against

- **An attacker who controls your user session and gets you to approve.** The prompt describes each request as well as the protocol allows, but you still have to read it.
- **root or kernel compromise** of the Mac.
- **Compromised servers**, or agent forwarding to them. Keep `ForwardAgent` off.
- **Destination checks without `publickey-hostbound`.** For older servers the agent cannot know where a signature will be used. The process chain shown in the prompt is informational and can be stale.
- **Loss of availability.** The Touch ID key is gone if the Mac fails, if fingerprints change under the `current-set` policy, or after `delete`. The emergency kit covers this only if it was stored outside the Mac.
- **Theft of the emergency kit together with its passphrase.** The emergency key is a regular software key: whoever has the kit and the passphrase can log in to every server that trusts it, without Touch ID. Its protection is the passphrase (about 119 bits when generated, bcrypt KDF with 200 rounds) and keeping the kit off the Mac, ideally apart from the passphrase.
- **A man in the middle during recovery** for servers whose host key was never recorded (entries recorded before host keys were stored, until their next `audit`).
- **Reading the local inventory on a stolen Mac.** `inventory.json` is plain JSON (mode `0600`) so the agent can use it without a passphrase. FileVault protects it at rest; `status` warns when FileVault is off.

## Security design

- **Key protection**: CryptoKit `SecureEnclave.P256.Signing.PrivateKey`, accessibility `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, flags `privateKeyUsage` plus `biometryCurrentSet` (default) or `biometryAny`. The Secure Enclave enforces the policy; editing the file or the binary cannot remove it.
- **Authorization**: a fresh `LAContext` for every signature, reuse duration 0, prompt cancelled after 60 s. Sign requests are serialized, so only one prompt is shown at a time.
- **Small protocol surface**: only `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST` are implemented. Everything else (add, remove, lock, extensions) gets `SSH_AGENT_FAILURE`. Messages are capped at 256 KiB, parsed strictly with bounds checks, and malformed input closes the connection.
- **Socket hygiene**: the agent refuses to replace a file that is not a socket or a socket another agent is serving, and removes its socket on exit.
- **Output checks**: every signature is verified against the public key before it is returned.
- **Untrusted text**: user names, namespaces, host names and process names are stripped of control characters and truncated before they reach the prompt or the log.
- **Logs**: time, event, process chain and outcome only. No key material, payloads, remote user names or hosts.
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
- **ssh config edits**: only after the user confirms. New `Host` blocks are appended; when lines are added to an existing block, the previous file is saved next to it as `.touchid-backup` first.
- **authorize and audit**: keys are appended by a small POSIX `sh` script that matches existing keys by blob, fixes a missing final newline and quotes only a restricted character set. The Touch ID check disables connection sharing (`ControlPath=none`), uses `BatchMode`, and confirms from `ssh -v` that the server accepted the Touch ID key's fingerprint, so another configured key cannot pass for it.

## Scope

In scope:

- signing without Touch ID approval, or extracting or using the key without it;
- crashes, hangs or memory-safety issues triggered through the socket;
- access to the agent from another local user;
- sensitive data reaching the log;
- the emergency key, its passphrase or the plaintext inventory left on disk or exposed to other processes;
- a prompt that misdescribes a request beyond the limitations documented here and in the README.

Out of scope:

- attacks that need root or physical access to an unlocked Mac;
- approving a prompt that correctly described the request;
- the documented limitations above;
- vulnerabilities in macOS or OpenSSH themselves (please report those upstream).

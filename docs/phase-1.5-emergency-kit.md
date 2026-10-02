# Phase 1.5: emergency kit and inventory

> Status: **implemented**. Phase 2 (temporary credentials for overnight agents) builds on it.

## Problem

The Touch ID key never leaves the Secure Enclave of one Mac. That is the point, but it means the key is gone if the Mac is stolen, breaks, or if the fingerprints change under the `current-set` policy. Without a second key on every server, losing the Mac means losing access. And if the only list of those servers lives on the Mac, it goes with it.

## What it does

| Piece | Where it lives | Who can read it |
| --- | --- | --- |
| Touch ID key | Secure Enclave (`identity.se` blob) | Nobody; it only signs, after Touch ID |
| Emergency key, private half | **Only in the kit**, outside the Mac | Whoever has the kit **and** the passphrase |
| Emergency key, public half | `~/.touchid-ssh-agent/recovery.pub` | Public |
| Inventory | `~/.touchid-ssh-agent/inventory.json` (`0600`) | This user; FileVault at rest |
| Inventory backup | `<backup folder>/inventory.age` | Only the emergency kit |

### setup

1. Creates the Touch ID key if there is none.
2. Asks for a backup folder, suggesting iCloud Drive when it exists, and explains why it should be synced to the cloud. Skipping is allowed after a warning and typing `SKIP`; `set backup-path DIR|none` changes it later.
3. Creates the emergency kit, or imports an existing public key.

### recovery create

1. Generates a passphrase: 6 groups of 4 characters from an alphabet without look-alikes, about 119 bits. It is shown once.
2. The user retypes it **exactly**. Normalizing it (dropping dashes, ignoring case) would let the user write down a form that later fails to open the kit, so the confirmation is strict. Three wrong attempts abort with nothing created.
3. The screen and scrollback are cleared.
4. `ssh-keygen -t ed25519 -a 200` generates the key in `~/.touchid-ssh-agent/kit/` (`0700`).
5. The kit file is assembled: the private key block first, then the instructions.
6. The kit is verified with `ssh-keygen -y` and the passphrase.
7. Finder reveals the kit. The user types `SAVED` (or `ABORT`).
8. `recovery.pub` is installed, the scratch directory is erased, and the backup is re-encrypted.

### authorize

1. `ssh -G` resolves the destination: hostname, user and port.
2. Using the access that already works (with optional extra ssh arguments after `--`), a POSIX `sh` script adds both keys to `authorized_keys`. It matches existing keys by blob, so nothing is duplicated, and fixes a missing final newline.
3. A login with only the Touch ID key (one Touch ID) confirms from `ssh -v` that the server accepted that key's fingerprint.
4. The inventory entry is saved and the backup is re-encrypted.

### audit

Logs in to each inventory server with the Touch ID key (one Touch ID each) and reports whether both keys are present. It records the result in the inventory.

## Decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Kit format | One text file: OpenSSH key block, then instructions | OpenSSH and age both read the key from the start of the file and ignore what follows the END line, so the kit works with `ssh -i` and `age -i` without editing. |
| Inventory encryption | age, to the emergency public key | The Mac can update the backup at any time without holding anything that decrypts it. age is an open format available on macOS, Linux and Windows. |
| Cloud storage | Any synced folder; no cloud API | Zero cost, and no cloud credential in the kit. Access is the user's own account, such as iCloud.com. |
| Passphrase handover | stdin of `ssh-keygen`, run without a controlling terminal | With a terminal, ssh-keygen reads passphrases from `/dev/tty` and ignores stdin (found by the expect tests). Command-line arguments and environment variables are visible to other processes. |
| Imported keys | ed25519 or rsa public keys only | Those are the SSH key types age can decrypt with. FIDO2 (`sk-`) keys would need a separate age identity in the kit. |
| Touch ID check | `ssh -v` fingerprint match, `ControlPath=none`, `BatchMode` | The user's ssh config may offer other keys that would also log in, and a shared connection would "log in" without authenticating at all. |

## Recovery procedure

The kit carries these steps, filled in with its fingerprints and backup folder:

1. `chmod 600 emergency-kit.txt`
2. Download `inventory.age` and decrypt it: `age -d -i emergency-kit.txt inventory.age`
3. Log in: `ssh -i emergency-kit.txt -p PORT USER@HOST`
4. Remove the lost Mac's login key from each server.
5. On a new Mac, run `setup` and `authorize` for every server.
6. Retire the emergency key that was used.

## Tests

- **Unit**: comment sanitizing, the install script, passphrase shape, key type validation, inventory and settings round trips.
- **ssh-keygen and age as oracles**:
  - the kit opens only with the exact passphrase;
  - no raw key is left behind;
  - age decrypts the backup with the kit and not with another key;
  - replacing the emergency key re-encrypts the backup.
- **expect (real pseudo-terminal)**:
  - `recovery create`: happy path, three wrong retypes, ABORT;
  - `setup` end to end;
  - age decrypting the backup with the passphrase-protected kit.
- **Docker sshd**:
  - `authorize` against a server that starts with a bootstrap key and an `authorized_keys` without a final newline;
  - keys added once;
  - the Touch ID check passes while a second valid key is configured;
  - the emergency key logs in on its own;
  - `audit` detects a missing emergency key and a missing login key;
  - the CLI's `authorize`, `audit` and `inventory`.

## Known limitations

- Replacing the emergency key does not remove the old one from servers. `authorize` installs the new key, and the old line must be removed by hand.
- The kit lists the backup folder it was created with. After `set backup-path`, note the new location next to the kit.
- `audit` costs one Touch ID per server.

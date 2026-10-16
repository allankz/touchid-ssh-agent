# Windows port: research notes and spike plan

> Status: **research, not scheduled**. Nothing here is implemented. The first step is the spike below, run on a real Windows 11 machine. Its results decide whether a Windows version can exist and what it can promise.

## Question

Can touchid-ssh-agent run on Windows with Windows Hello in place of Touch ID, and what would it really guarantee?

## What the Mac version promises

1. **The key cannot leave the hardware.** It is generated inside the Secure Enclave.
2. **The hardware enforces biometry on every signature.** The requirement is sealed into the key. Neither the agent nor root can sign without a finger; root can only ask. (Since 0.2.0, temporary access is a deliberate, approved exception: one Touch ID lets a short-lived software key log in for a limited time. A Windows version would decide separately whether to offer it.)
3. **The prompt says what is being approved**: remote user, server, requesting process chain.
4. **Any OpenSSH server works.** It only needs an `ecdsa-sha2-nistp256` line in `authorized_keys`.

No Windows route found so far gives all four at once.

## Routes

| Route | Key | What it gives | Catch |
| --- | --- | --- | --- |
| **1. `KeyCredentialManager`** (WinRT Windows Hello API) | RSA-2048 in the Microsoft Passport KSP, in the TPM when there is one | Supported public API; Hello prompt on `RequestSignAsync` | The docs say signatures are **RSA-PSS**/SHA-256. SSH `rsa-sha2-256` requires **PKCS#1 v1.5** (RFC 8332), so the server would reject them. The docs say "supports operations like", not "only", so only a test settles it. No parameter for the prompt text. |
| **2. NCrypt on the Passport KSP** (the same keys, opened with `NCryptOpenKey`) | Same | Padding chosen per call (`BCRYPT_PAD_PKCS1`). According to one Microsoft Q&A poster (unverified), `NCRYPT_USE_CONTEXT_PROPERTY` sets the prompt text and `NCRYPT_WINDOW_HANDLE_PROPERTY` the owner window | Partly undocumented. Dirk-jan Mollema showed a same-user process signing with the Windows Hello for Business **login** key through NCrypt with **no prompt**, from cached data. Unknown for app keys; until tested, promise 2 may not hold. |
| **3. WebAuthn platform authenticator** (`webauthn.dll`) with `sk-ecdsa-sha2-nistp256@openssh.com` | P-256 passkey held by Hello | User verification on every assertion, enforced by Windows | Servers need OpenSSH ≥ 8.2, and ≥ 8.4 for `verify-required`. The prompt shows only the RP ID (`ssh:`), never "admin on server.example". Win32-OpenSSH's own Hello path is unreliable: mixed results in issue #2040, broken after 25H2 in issue #2408. Calling `webauthn.dll` from our agent avoids Win32-OpenSSH's code, not Windows' behavior. |

**Rejected:** a TPM key from the Microsoft Platform Crypto Provider, with our own Hello check (`UserConsentVerifier`) before each signature. The check would live in our process, not in the key: any process of the user can call NCrypt on that key and sign without it. (nCryptAgent uses this provider with a PIN policy, not Hello.)

**Outside Hello, worth supporting anyway:** a hardware FIDO key (YubiKey) with `sk-ssh-ed25519@openssh.com`. It is the strongest option on Windows: the touch and the PIN are enforced by the device, so not even an admin on the PC can sign without the user. It has the same server requirement as route 3. Inventory, kit, `authorize`, `audit` and `recover` add the same value around it.

## Spike

**Setup**

- A physical Windows 11 PC with TPM 2.0, and Windows Hello with fingerprint or face plus PIN. Run the tests as a standard user, then repeat the relevant ones as an admin.
- For test 4, a VM without a virtual TPM.
- An OpenSSH ≥ 8.4 server for the login checks. The `Tests/e2e` image (Alpine 3.22) works.
- Throwaway code. C# (.NET with a Windows SDK target framework, for WinRT) or C++ is fastest; it does not need to be Swift.
- Write the results in [Results](#results-fill-in-during-the-spike) at the end of this file.

### Test 1: PKCS#1 v1.5 signatures

1. Create a key with `KeyCredentialManager.RequestCreateAsync("touchid-ssh-agent-spike", KeyCredentialCreationOption.ReplaceExisting)`.
2. Export the public key with `RetrievePublicKey()` (X.509 SubjectPublicKeyInfo, DER) and convert it to `pub.pem`.
3. Sign a fixed 64-byte `msg.bin` with `RequestSignAsync`, save `sig.bin`, and check which padding it uses:

   ```bash
   openssl dgst -sha256 -verify pub.pem -signature sig.bin msg.bin
   ```

   ```bash
   openssl dgst -sha256 -verify pub.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto -signature sig.bin msg.bin
   ```

   The first command checks PKCS#1 v1.5, the second PSS. If neither verifies, try again with `msg.bin` replaced by its SHA-256, in case the API expects a hash.
4. Find the same key in the Passport KSP (`certutil -csp "Microsoft Passport Key Storage Provider" -key`). Open it with `NCryptOpenKey` and sign `SHA-256(msg.bin)` with `NCryptSignHash`, `BCRYPT_PAD_PKCS1` and `BCRYPT_PKCS1_PADDING_INFO { pszAlgId = BCRYPT_SHA256_ALGORITHM }`. Check it with the first command.
5. Optional: try to create an ECDSA P-256 key directly in the Passport KSP with `NCryptCreatePersistedKey`. If that works, Windows can use the same `ecdsa-sha2-nistp256` key type as the Mac.

**Pass:** route 1 or route 2 produces a signature that the PKCS#1 v1.5 command accepts.

### Test 2: a prompt on every signature, from every process

This test decides whether the Windows version can make promise 2.

Run each step from the process that created the key, and from a second, unrelated process of the same user that opens the key itself: with `NCryptOpenKey` (PowerShell with P/Invoke is enough), and with `KeyCredentialManager.OpenAsync` from another executable.

1. Sign 5 times in a row, a few seconds apart. Every call must show Hello.
2. Sign right after approving a prompt in the other process. It must still show Hello, with no shared cache.
3. Lock the screen, unlock it with the PIN, then sign. It must show Hello.
4. Repeat from an elevated process and as SYSTEM (`psexec -s`). This is expected to fail. Record what happens: it decides what SECURITY.md says about admins.

Also record whether Hello always offers the PIN next to biometry, and whether anything turns the PIN off for this key.

**Pass:** steps 1–3 show a prompt every time, in every process. A single signature without a prompt in steps 1–3 rules out that route.

### Test 3: prompt text and focus

1. Before signing, set `NCRYPT_USE_CONTEXT_PROPERTY` to a sample reason such as `log in over SSH as admin to server.example, requested by ssh ← pwsh ← WindowsTerminal`. Check that it appears and that characters like `←` render.
2. Run the signer as a background process started at logon (scheduled task, no console window), with `NCRYPT_WINDOW_HANDLE_PROPERTY` set to a hidden window of its own. Sign while a terminal has focus.

**Pass:** the text is shown, and the prompt comes to the front in at least 9 of 10 attempts.

- If only the text fails, the Windows prompt says less than the Mac's. That is a documented limitation, not a blocker.
- If focus fails, the agent needs a notification or tray icon telling the user to look for the prompt. nCryptAgent documents the same problem.

### Test 4: TPM or software

1. Run `certutil -csp "Microsoft Passport Key Storage Provider" -key -v` and read `NgcKeyImplType` for the spike key.
2. Find a check the agent can run by itself at `setup`: an NCrypt property on the key, or `KeyCredential.GetAttestationAsync`.
3. Repeat on the VM without a TPM. Hello should still work there, with a software key.

**Pass:** the agent can tell a TPM key from a software key without the user's help. `setup` must refuse a software key.

### Test 5: what deletes the key

Create the key, run each event, then check whether the key still opens and signs.

| Event | Expected | Result |
| --- | --- | --- |
| Change the Hello PIN | Kept | |
| "I forgot my PIN" reset | Probably deleted (default for Windows Hello for Business) | |
| Add or remove a fingerprint | Unknown | |
| Turn Windows Hello off and on | Deleted | |
| Windows feature update | Kept | |
| Clear the TPM (Windows Security) | Deleted | |
| BIOS or firmware update | Kept, unless it resets the firmware TPM | |

The results feed the README's availability section and the agent's error messages.

### Test 6: WebAuthn route (only if test 1 or 2 fails)

1. From a small program, call `WebAuthNAuthenticatorMakeCredential` with RP ID `ssh:`, platform attachment, user verification required, ES256. Does Windows go straight to Hello, or show the phone/USB chooser from the 25H2 report?
2. Call `WebAuthNAuthenticatorGetAssertion` with the message as `pbClientDataJSON`. Windows hashes it with SHA-256, which should match the message hash OpenSSH expects. Build an `sk-ecdsa-sha2-nistp256@openssh.com` signature (ECDSA signature, flags, counter) and log in to the test server with `verify-required` in `authorized_keys`.
3. Repeat test 2, steps 1–2.

**Pass:** a login with `verify-required` succeeds after a Hello prompt, on the current Windows build, with a prompt on every signature.

### Test 7: transport

No agent of our own is needed for this one. Pageant's `--openssh-config` points Windows OpenSSH at a custom named pipe through `IdentityAgent`, which is the same mechanism we would use.

1. With `IdentityAgent \\.\pipe\<name>` in `%USERPROFILE%\.ssh\config`, check that `C:\Windows\System32\OpenSSH\ssh.exe` lists identities from the custom pipe while the built-in OpenSSH Authentication Agent service keeps running.
2. Check `ssh-add -L` with `SSH_AUTH_SOCK` set to the pipe.
3. Check Git for Windows with `core.sshCommand` pointing to the Windows `ssh.exe`.

**Pass:** all three reach the custom pipe.

### Decision

| Outcome | Next step |
| --- | --- |
| Tests 1 and 2 pass (route 1 or 2) | Build the Windows version on that route. Same model as the Mac: standard key type, any server, a prompt per signature. Test 3 decides how much the prompt can say. |
| Test 1 or 2 fails, test 6 passes | `sk-ecdsa` route. Servers need OpenSSH ≥ 8.4, the prompt cannot describe the request, and `authorize` must check the server version first. |
| Test 6 fails too | No Windows Hello version. Offer a hardware FIDO key on Windows instead, with inventory, kit and recovery around it. |
| Test 4 fails | Blocks every Hello route: a software key would break promise 1 without the user knowing. |

Test 2, step 4 (admin and SYSTEM) blocks nothing, but it decides what SECURITY.md says.

## Security compared with the Mac

"Best case" means tests 1–4 pass. "Worst case" means they do not, or the machine has no TPM.

| Threat | Mac | Windows, best case | Windows, worst case |
| --- | --- | --- | --- |
| Malware or a poisoned package copies the key from disk | Protected | Protected (TPM) | Not protected without a TPM; `setup` must refuse |
| Key moved to another computer | Protected | Protected | Not protected without a TPM |
| An AI agent or a script using `ssh` normally | Asks for a finger | Asks for Hello | Asks for Hello |
| Malicious code in the session using the key without the user | Only a finger approves | The PIN also approves, and a keylogger can capture it | Not protected if the key signs without a prompt |
| Attacker with admin rights | Out of scope in SECURITY.md, but the Secure Enclave still requires the finger (root can only alter what the prompt says) | Probably not protected: research shows SYSTEM recovering the intermediate PINs that unlock Hello keys | Not protected |
| The user approves without knowing what | The prompt describes the request | Same, if the custom text works | Generic prompt (`ssh:`) |
| Another local user | Socket `0600` and UID check | Pipe DACL and SID check | Same |

Differences no route fixes:

- **Windows Hello always offers the PIN.** There is no equivalent of hiding the fallback (`localizedFallbackTitle = ""` in `Signer.swift`). The Hello dialog does not run on a secure desktop.
- **No equivalent of `biometryCurrentSet`**, which invalidates the key when fingerprints change.
- **Admin is closer to the user on Windows.** Many developers use an admin account with UAC, and Microsoft does not treat UAC as a security boundary.

The honest promise for Windows: "the key cannot be stolen from the disk or copied to another machine, and every use asks for Windows Hello". Not "only your finger can approve". The README for Windows has to say this rather than repeat the Mac's promises.

## Availability

The emergency kit, the inventory and `recover` do not depend on how the main key is stored. So the risk of being locked out is the same as on the Mac: losing the main key **and** the kit or its passphrase, or someone removing the emergency key from a server with no `audit` to notice.

What changes is how often the main key is lost (test 5). On the Mac that happens when the Mac is lost, when fingerprints change under `current-set`, or after `deauthorize --all`. On Windows, a TPM clear, a Windows reset, a forgotten PIN or turning Hello off can also delete it. A Windows update can also break the route without deleting the key, as 25H2 did for `sk-ecdsa` through Hello. On Windows, `recover` will not be a rare event.

Requirements before a Windows release:

1. `recover` and `recovery test` work on Windows from the first release.
2. When the key is missing or unusable, the agent says so and points to `recover`, instead of failing every signature with a generic error.
3. A second everyday key (a FIDO key, or another computer), so a broken Hello does not leave the kit as the only way in. The kit is meant to stay put away.
4. `status` reminds the user to run `recovery test` periodically.

## Code impact

Whatever the route, `TouchIDSSHCore` splits into a portable core and a platform layer.

**Portable** (as is, or with small changes): `SSHWire`, `AgentProtocol`, `SSHKeyFormat` (CryptoKit → swift-crypto), `SignedPayload`, `PromptText`, `Inventory`, and, minus their hard-coded `/usr/bin/ssh` and `/usr/bin/ssh-keygen` paths, `SSHConfig`, `RemoteKeys` and `Recovery`.

**Per platform:**

| Concern | Mac today | Windows |
| --- | --- | --- |
| Key and signature | `IdentityStore`, `Signer`: CryptoKit Secure Enclave, LocalAuthentication | The chosen route: NCrypt, `KeyCredentialManager` or `webauthn.dll` |
| Transport | `AgentServer`: Unix socket `0600` in a `0700` directory, `getpeereid` | Named pipe with a DACL for the user's SID only, `FILE_FLAG_FIRST_PIPE_INSTANCE` (so no other process can create the pipe first), `PIPE_REJECT_REMOTE_CLIENTS`, and a check of the client's SID |
| Requester chain | `PeerProcess`: `LOCAL_PEERPID`, `proc_pidinfo` | `GetNamedPipeClientProcessId`, parent pids from a Toolhelp32 snapshot |
| Autostart | `LaunchAgent` (launchd) | Scheduled task at logon, or `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Not a Windows service: Hello cannot prompt from session 0 |
| External tools | `Command`: `posix_spawn`, hard-coded `/usr/bin/ssh*`, `/bin/launchctl`, and a new session (`setsid`) so `ssh-keygen` reads the kit passphrase from stdin | `CreateProcess`, tools looked up in `%SystemRoot%\System32\OpenSSH`. The passphrase handover must be redone, for example a detached process with no console (unverified) |
| Terminal | `Terminal.swift`: termios | Console API |
| Kit during recovery | `EmergencyAgent`: a throwaway `/usr/bin/ssh-agent -D -a` | Win32 `ssh-agent.exe` runs as a system service, so: an in-process agent holding the decrypted kit key (needs OpenSSH private key decryption, bcrypt-pbkdf + aes256-ctr, and Ed25519 signing), or `ssh -i kit` with a passphrase prompt per server |
| Backup folder suggestion | iCloud Drive | OneDrive (`%OneDrive%`) |
| Git commit signing | Wrapper around `/usr/bin/ssh-keygen` | `.cmd` wrapper around the Windows `ssh-keygen.exe`. Git for Windows' bundled ssh cannot reach a named pipe, so `core.sshCommand` must point to Windows OpenSSH |

**Language.** Swift on Windows is viable: there is an official toolchain with Foundation, and the Win32 C APIs (NCrypt, named pipes, `webauthn.h`) come through the `WinSDK` module. WinRT (`KeyCredentialManager`) is harder from Swift: swift-winrt, or a small C++/WinRT target behind a C API. swift-crypto would be a dependency only on Windows (`.when(platforms: [.windows])`), so the Mac build keeps working with the Command Line Tools alone.

**One codebase is a goal in itself.** It keeps the kit, `inventory.json` and `inventory.age` formats identical, so `recover` on Windows after losing a Mac works, and the reverse.

**Later, not in a first version:** WSL (a relay such as npiperelay + socat), and the Pageant protocol for PuTTY.

## Open questions

- With `KeyCredentialManager`, which "application" owns the key for an unpackaged desktop executable, and can another executable open it? (Test 2.)
- Can the Passport KSP create an ECDSA P-256 key directly? (Test 1, step 5.)
- Does Enhanced Sign-in Security (biometrics isolated with VBS) change anything for app keys?
- Can the Hello PIN fallback be turned off for one key? Probably not.

## Results (fill in during the spike)

- Date, Windows build, PC model, TPM vendor and version:
- Test 1:
- Test 2:
- Test 3:
- Test 4:
- Test 5: see the table above.
- Test 6:
- Test 7:
- Decision:

## Sources

- [KeyCredentialManager.OpenAsync: RSA-2048, PSS with SHA-256](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredentialmanager.openasync)
- [KeyCredential.RequestSignAsync](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredential.requestsignasync)
- [Undocumented usage of the NCrypt API for the Microsoft Passport KSP (Microsoft Q&A)](https://learn.microsoft.com/en-gb/answers/questions/2100684/undocumented-usage-of-ncrypt-api-for-microsoft-pas)
- [Borrowing Windows Hello keys for authentication and persistence (Dirk-jan Mollema)](https://dirkjanm.io/borrowing-windows-hello-keys/)
- [Checking Windows Hello key storage: TPM or software (Helge Klein)](https://helgeklein.com/blog/checking-windows-hello-for-business-whfb-key-storage-tpm-hardware-or-software/)
- [Windows Hello for Business: PIN reset](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/pin-reset)
- [Win32-OpenSSH issue #2040](https://github.com/PowerShell/Win32-OpenSSH/issues/2040) and [issue #2408](https://github.com/PowerShell/Win32-OpenSSH/issues/2408)
- [nCryptAgent](https://github.com/unreality/nCryptAgent/)
- [openssh-sk-winhello](https://github.com/tavrez/openssh-sk-winhello)

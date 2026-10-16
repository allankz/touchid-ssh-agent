# Temporary SSH access: prototype validation

> Protocol feasibility check on 2026-10-15, made before the feature existed. The implemented feature and its validation are described in the [implementation record](phase-2-implementation.md); this probe still runs unchanged as a regression check of the protocol path.

## What the probe exercises

`scripts/verify-temporary-access-design.py` compiles an isolated Swift executable using the existing `SSHWire`, `SSHKeyFormat` and `AgentProtocol` sources. The executable creates a real Secure Enclave P-256 CA and an Ed25519 temporary key, constructs and signs one certificate, and serves signatures from memory over a Unix socket. The temporary private key is never serialized by the probe.

The test CA deliberately uses `privateKeyUsage` **without biometric flags**, in a disposable process, to exercise hardware signing without requesting approval. It is not persisted or offered on the agent socket. This validates the signature path, not Touch ID behavior. The login and recovery test keys are newly generated software stand-ins; no installed identities, user SSH configuration or real hosts are read or modified.

The Python harness creates three Docker servers. Each initially trusts only its test login and recovery public keys. It then uses the test login key over SSH to append a single scoped CA trust line to each account. One certificate permits the first two targets; the third accepts a different principal.

## Measured result

**PASS:** all required checks passed. The run issued one certificate with **one Secure Enclave CA signature** and made **six temporary-key signatures**. Two selected targets accepted repeated connections; the third was rejected. The certificate lifetime was 30 seconds. Biometric approval was not exercised.

## Checks

The probe checks:

- The two original keys authenticate before enrollment.
- A temporary certificate fails while the server has only those two public keys.
- Enrollment appends exactly one CA trust line, preserving the previous file contents byte for byte, including blank lines.
- A certificate signed by the Secure Enclave is accepted on both selected targets for repeated SSH commands, using the returned-style config and a memory-only private key.
- The same certificate is rejected by the unselected third target, and the bare temporary key is rejected too.
- Default restrictions reject PTY allocation and remote port forwarding.
- Original login/recovery keys still authenticate, and no server key-file changes are needed between temporary connections.
- The CA is absent from the temporary socket's identity list. One CA signature issues the multi-target certificate; repeated authentication uses the temporary key instead.
- Certificate expiry rejects fresh SSH authentication on the server.
- An agent connection opened before expiry cannot obtain a signature after expiry. The probe intentionally leaves the expired socket running to exercise this guard.
- Stopping the probe removes its socket. An already authenticated SSH command continues past expiry and agent stop, matching the documented limitation.

## Reproduction

Requires an unlocked Mac with Secure Enclave, Swift Command Line Tools, Docker and Python 3. The probe does not lock the screen or prompt for Touch ID. From the repository root:

```bash
# Build the existing disposable-server image if it is not already available.
docker build -t touchid-ssh-agent-e2e:local Tests/e2e
python3 -B scripts/verify-temporary-access-design.py
```

The script prints its measured results as JSON and fails if a required check fails. It uses temporary directories under `/tmp` and containers bound only to loopback. Cleanup removes those directories and containers, leaving the reusable e2e image.

## Additional alias/config check

An isolated `ssh -G -F <fixture-config>` check verified that a dated alias such as `app-server-access-20261015-a1b2c3d4e5f6` resolves to the intended hostname, account, port, temporary identity and certificate. Removing that fixture config makes the old explicit `-F` command fail, while its separate personal-config fixture remains unchanged.

The check also confirmed that including the same file from a personal config with `Host * IdentityFile ...` inherits an additional identity. This supports keeping grant configs separate and returning full `-F` argv in the first version. It does not validate the future alias generator, inventory integration or cleanup implementation.

## Pre-implementation checkpoint

Before the Phase 2 handoff commit, `make test` passed all **37 existing tests**. Markdown structure, local file/section links, JSON examples and the probe's Python syntax were checked as well. This verifies the existing baseline alongside the separately recorded prototype results; it does not turn any pending Phase 2 command or manual biometric check into completed implementation.

## Not established by this probe

- Actual Touch ID approval, denial, timeout or the number of native prompts. These require a biometric CA and interactive testing.
- Production `access`, `instructions`, JSON error handling, target parsing, inventory enrollment, audit, deauthorization or recovery integration. They remain planned commands and behaviors.
- launchd startup, cancellation/readiness, automatic expiry teardown, screen lock, logout, sleep/wake or power-management behavior. The probe runs as a child process and deliberately keeps an expired socket available for a negative test.
- ProxyJump or arbitrary existing SSH configurations and server authentication policies. Only explicit generated configurations and the disposable e2e server policy are tested here.

The protocol and hardware signature path are testable now. Full feature acceptance still requires implementing and testing the remaining lifecycle and integration work in the [Phase 2 design](phase-2-temporary-credentials.md).

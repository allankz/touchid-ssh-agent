#!/usr/bin/env python3
"""Disposable Phase 2 protocol probe, not the access feature.

Requires macOS/Secure Enclave, Swift and the existing Docker e2e image.
The test CA uses real Secure Enclave signing WITHOUT biometric protection.
No installed identity, user SSH configuration or real server is accessed.
"""

import base64
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import tempfile
import time


REPOSITORY = Path(__file__).resolve().parents[1]
IMAGE = "touchid-ssh-agent-e2e:local"

# Reuses the production SSH codec/agent protocol. This executable deliberately
# keeps an expired socket alive to test the per-request expiry guard, then exits
# on SIGTERM. It does not implement launchd or the proposed production CLI.
SWIFT_PROBE = r'''
import CryptoKit
import Darwin
import Foundation
import Security

func uint64(_ value: UInt64, _ writer: inout SSHWriter) {
    writer.writeUInt32(UInt32(truncatingIfNeeded: value >> 32))
    writer.writeUInt32(UInt32(truncatingIfNeeded: value))
}

func exactly(_ fd: Int32, _ count: Int) -> Data? {
    var bytes = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let result = bytes.withUnsafeMutableBytes {
            read(fd, $0.baseAddress! + offset, count - offset)
        }
        if result > 0 { offset += result }
        else if result < 0 && errno == EINTR { continue }
        else { return nil }
    }
    return Data(bytes)
}

func send(_ fd: Int32, _ body: Data) -> Bool {
    let frame = AgentProtocol.frame(body)
    var offset = 0
    while offset < frame.count {
        let count = frame.withUnsafeBytes {
            write(fd, $0.baseAddress! + offset, frame.count - offset)
        }
        if count > 0 { offset += count }
        else if count < 0 && errno == EINTR { continue }
        else { return false }
    }
    return true
}

final class ProbeAgent {
    let folder: URL
    let key = Curve25519.Signing.PrivateKey()
    let expiresAt: UInt64
    let caBlob: Data
    let keyBlob: Data
    let certificate: Data
    let lock = NSLock()
    var signatures = 0
    var expiredRejections = 0

    init(_ directory: String) throws {
        folder = URL(fileURLWithPath: directory)
        expiresAt = UInt64(Date().timeIntervalSince1970) + 30
        guard SecureEnclave.isAvailable else {
            throw NSError(domain: "DesignProbe", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Secure Enclave unavailable"])
        }
        // TEST ONLY: hardware signing, with no Touch ID prompt. Nothing from this
        // identity is persisted except its public key; never use as a real CA.
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
        )!
        let ca = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        caBlob = SSHKeyFormat.publicKeyBlob(ca.publicKey)
        var raw = SSHWriter()
        raw.writeString("ssh-ed25519")
        raw.writeString(key.publicKey.rawRepresentation)
        keyBlob = raw.data

        var nonce = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess
        else { throw NSError(domain: "DesignProbe", code: 2) }
        var cert = SSHWriter()
        cert.writeString("ssh-ed25519-cert-v01@openssh.com")
        cert.writeString(Data(nonce))
        cert.writeString(key.publicKey.rawRepresentation)
        uint64(1, &cert)
        cert.writeUInt32(1)
        cert.writeString("access-design-probe")
        var principals = SSHWriter()
        principals.writeString("access-target-a")
        principals.writeString("access-target-b")
        cert.writeString(principals.data)
        uint64(UInt64(Date().timeIntervalSince1970) - 60, &cert)
        uint64(expiresAt, &cert)
        cert.writeString(Data()) // critical options
        cert.writeString(Data()) // extensions: deny PTY/forwarding/user RC
        cert.writeString(Data()) // reserved
        cert.writeString(caBlob)
        let signed = try ca.signature(for: cert.data)
        guard ca.publicKey.isValidSignature(signed, for: cert.data)
        else { throw NSError(domain: "DesignProbe", code: 3) }
        cert.writeString(try SSHKeyFormat.signatureBlob(rawRS: signed.rawRepresentation))
        certificate = cert.data
        for (name, blob) in [("ca.pub", caBlob), ("key.pub", keyBlob),
                             ("key-cert.pub", certificate)] {
            let line = SSHKeyFormat.authorizedKeyLine(blob: blob, comment: "design-probe")
            try Data((line + "\n").utf8).write(to: folder.appendingPathComponent(name))
        }
        try metrics()
    }

    func metrics() throws {
        let value: [String: Any] = [
            "ca_backend": "SecureEnclave.P256",
            "biometric_policy_tested": false,
            "ca_signatures": 1,
            "temporary_signatures": signatures,
            "expired_rejections": expiredRejections,
            "expires_at_epoch": expiresAt
        ]
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            .write(to: folder.appendingPathComponent("state.json"), options: .atomic)
    }

    func handle(_ body: Data) -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard let request = try? AgentProtocol.parseRequest(body) else { return AgentProtocol.failure }
        switch request {
        case .requestIdentities:
            return AgentProtocol.identitiesAnswer([(keyBlob, "temporary"), (certificate, "temporary-cert")])
        case .sign(let blob, let data, let flags):
            guard blob == keyBlob || blob == certificate, flags == 0 else { return AgentProtocol.failure }
            guard Date().timeIntervalSince1970 < Double(expiresAt) else {
                expiredRejections += 1
                try? metrics()
                return AgentProtocol.failure
            }
            guard let signature = try? key.signature(for: data) else { return AgentProtocol.failure }
            signatures += 1
            try? metrics()
            var result = SSHWriter()
            result.writeString("ssh-ed25519")
            result.writeString(signature)
            return AgentProtocol.signResponse(signatureBlob: result.data)
        default:
            return AgentProtocol.failure
        }
    }

    func serve(_ fd: Int32) {
        defer { close(fd) }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { return }
        while let prefix = exactly(fd, 4) {
            let length = prefix.reduce(0) { $0 << 8 | Int($1) }
            guard length > 0, length <= AgentProtocol.maxMessageLength,
                  let body = exactly(fd, length), send(fd, handle(body)) else { return }
        }
    }
}

do {
    guard CommandLine.arguments.count == 2 else { throw NSError(domain: "DesignProbe", code: 4) }
    let agent = try ProbeAgent(CommandLine.arguments[1])
    signal(SIGPIPE, SIG_IGN)
    let file = agent.folder.appendingPathComponent("agent.sock").path
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let pathBytes = Array(file.utf8)
    guard fd >= 0, pathBytes.count < MemoryLayout.size(ofValue: address.sun_path)
    else { throw NSError(domain: "DesignProbe", code: 5) }
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard bound == 0, chmod(file, 0o600) == 0, listen(fd, 8) == 0
    else { throw NSError(domain: "DesignProbe", code: 6) }
    let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    signal(SIGTERM, SIG_IGN)
    source.setEventHandler {
        unlink(file)
        exit(0)
    }
    source.resume()
    print("READY")
    fflush(stdout)
    while true {
        let client = accept(fd, nil, nil)
        if client >= 0 { Thread { agent.serve(client) }.start() }
    }
} catch {
    fputs("Design probe failed: \(error)\n", stderr)
    exit(1)
}
'''


def run(args, *, check=True, stdin=None, timeout=25):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr[-2000:]}")
    return result


def verify():
    containers = []
    probe = None
    active = None
    held_socket = None
    # Short paths also fit macOS's Unix socket length limit.
    with tempfile.TemporaryDirectory(prefix="tsa-check-", dir="/tmp") as scratch:
        folder = Path(scratch)
        grant = folder / "grant"
        grant.mkdir(mode=0o700)
        try:
            source = folder / "main.swift"
            source.write_text(SWIFT_PROBE)
            print("Compiling a disposable Secure Enclave / memory-only agent probe...", flush=True)
            run(["swiftc", "-swift-version", "5", *[
                str(REPOSITORY / "Sources/TouchIDSSHCore" / name)
                for name in ("SSHWire.swift", "SSHKeyFormat.swift", "AgentProtocol.swift")
            ], str(source), "-o", str(folder / "probe")], timeout=90)
            main_key, recovery_key = folder / "main", folder / "recovery"
            for key in (main_key, recovery_key):
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
            original = main_key.with_suffix(".pub").read_text() + recovery_key.with_suffix(".pub").read_text()
            for _ in range(3):
                containers.append(run(["docker", "run", "-d", "--rm", "-p", "127.0.0.1::22",
                                       "-e", "AUTHORIZED_KEYS=" + original, IMAGE]).stdout.strip())
            ports = [run(["docker", "port", cid, "22/tcp"]).stdout.strip().rsplit(":", 1)[1]
                     for cid in containers]
            known = folder / "known_hosts"
            with known.open("w") as output:
                for cid, port in zip(containers, ports):
                    host_key = run(["docker", "exec", cid, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]).stdout
                    output.write(f"[127.0.0.1]:{port} {host_key}")
            common = ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                      "-o", "ControlPath=none", "-o", "StrictHostKeyChecking=yes",
                      "-o", "UserKnownHostsFile=" + str(known), "-o", "GlobalKnownHostsFile=/dev/null",
                      "-o", "ConnectTimeout=3"]

            def original_access(key, index):
                return common + ["-o", "IdentityAgent=none", "-i", str(key), "-p", ports[index],
                                 "tester@127.0.0.1"]

            for attempt in range(30):
                ready = run(original_access(main_key, 0) + ["true"], check=False)
                if ready.returncode == 0:
                    break
                time.sleep(0.1)
            assert ready.returncode == 0, ready.stderr
            evidence = {"image": IMAGE, "main_and_recovery_work_before": all(
                run(original_access(key, 0) + ["true"], check=False).returncode == 0
                for key in (main_key, recovery_key))}
            initial_keys = [run(["docker", "exec", cid, "cat", "/home/tester/.ssh/authorized_keys"]).stdout
                            for cid in containers]
            probe = subprocess.Popen([str(folder / "probe"), str(grant)], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            selector = selectors.DefaultSelector()
            selector.register(probe.stdout, selectors.EVENT_READ)
            try:
                if not selector.select(15) or probe.stdout.readline().strip() != "READY":
                    probe.terminate()
                    _, error = probe.communicate(timeout=5)
                    raise RuntimeError("Memory agent did not start: " + error)
            finally:
                selector.close()
            state = json.loads((grant / "state.json").read_text())
            evidence["ca_backend"] = state["ca_backend"]
            evidence["biometric_policy_tested"] = state["biometric_policy_tested"]
            ca = (grant / "ca.pub").read_text().strip()
            key_blob = (grant / "key.pub").read_text().split()[1]
            certificate = run(["ssh-keygen", "-Lf", str(grant / "key-cert.pub")]).stdout
            evidence["certificate_contains_both_principals"] = all(
                value in certificate for value in ("access-target-a", "access-target-b"))
            configuration = grant / "ssh_config"
            blocks = []
            for index, port in enumerate(ports):
                blocks.append(f"""Host target-{index}
  HostName 127.0.0.1
  User tester
  Port {port}
  IdentityAgent {grant / 'agent.sock'}
  IdentityFile {grant / 'key.pub'}
  CertificateFile {grant / 'key-cert.pub'}
  IdentitiesOnly yes
  PreferredAuthentications publickey
  BatchMode yes
  ForwardAgent no
  ControlMaster no
  ControlPath none
  ControlPersist no
  StrictHostKeyChecking yes
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  ConnectTimeout 3
""")
            configuration.write_text("\n".join(blocks))

            def temporary_access(index, extra=()):
                return ["ssh", "-F", str(configuration), *extra, f"target-{index}"]

            evidence["temporary_rejected_with_only_existing_two_keys"] = (
                run(temporary_access(0) + ["true"], check=False).returncode != 0)
            print("Confirmed: the existing two public keys do not accept the temporary certificate.", flush=True)
            ca_lines = []
            for index, cid in enumerate(containers):
                principal = f"access-target-{'abc'[index]}"
                line = (f'cert-authority,principals="{principal}",no-agent-forwarding,'
                        f'no-port-forwarding,no-X11-forwarding,no-user-rc {ca}\n')
                ca_lines.append(line)
                run(original_access(main_key, index) + ["cat >> .ssh/authorized_keys"], stdin=line)
            installed = [run(["docker", "exec", cid, "cat", "/home/tester/.ssh/authorized_keys"]).stdout
                         for cid in containers]
            evidence["one_ca_line_added_existing_keys_unchanged"] = all(
                value == before + line
                for value, before, line in zip(installed, initial_keys, ca_lines))
            assert evidence["one_ca_line_added_existing_keys_unchanged"]
            evidence["repeated_access_to_selected_hosts"] = all(
                run(temporary_access(index) + ["printf accepted"]).stdout == "accepted"
                for index in (0, 1, 0, 1))
            evidence["unselected_host_rejected"] = (
                run(temporary_access(2) + ["true"], check=False).returncode != 0)
            evidence["bare_temporary_key_rejected"] = (
                run(temporary_access(0, ["-o", "PubkeyAcceptedAlgorithms=ssh-ed25519"]) + ["true"],
                    check=False).returncode != 0)
            forwarded = run(temporary_access(0, ["-N", "-o", "ExitOnForwardFailure=yes", "-R",
                                                  "127.0.0.1:0:127.0.0.1:22"]), check=False)
            evidence["port_forwarding_rejected"] = forwarded.returncode != 0 and "forwarding failed" in forwarded.stderr
            pty = run(temporary_access(0, ["-tt"]) + ["true"], check=False)
            evidence["pty_rejected"] = "PTY allocation request failed" in pty.stderr
            evidence["main_and_recovery_still_work"] = all(
                run(original_access(key, 0) + ["true"], check=False).returncode == 0
                for key in (main_key, recovery_key))
            evidence["server_key_files_unchanged_between_connections"] = all(
                run(["docker", "exec", cid, "cat", "/home/tester/.ssh/authorized_keys"]).stdout == value
                for cid, value in zip(containers, installed))
            listing_env = dict(os.environ, SSH_AUTH_SOCK=str(grant / "agent.sock"))
            listing = subprocess.run(["ssh-add", "-L"], env=listing_env, text=True,
                                     capture_output=True, check=True).stdout
            evidence["ca_not_exposed_on_temporary_socket"] = ca.split()[1] not in listing
            evidence["no_temporary_private_key_file"] = not any(
                b"PRIVATE KEY" in entry.read_bytes() for entry in grant.iterdir()
                if entry.is_file() and not entry.is_socket())
            state = json.loads((grant / "state.json").read_text())
            evidence["ca_signatures_for_multi_host_grant"] = state["ca_signatures"]
            evidence["temporary_agent_signatures"] = state["temporary_signatures"]
            print("Secure Enclave certificate and memory-only agent accepted; multi-host scope and key preservation passed.", flush=True)
            # Leave an agent connection open to ensure expiry checks do not
            # apply only to clients connecting after the deadline.
            held_socket = socket.socket(socket.AF_UNIX)
            held_socket.settimeout(5)
            held_socket.connect(str(grant / "agent.sock"))
            seconds = max(1, int(state["expires_at_epoch"] - time.time()) + 3)
            active = subprocess.Popen(temporary_access(0) + [
                f'printf "STARTED\\n"; sleep {seconds}; printf "SURVIVED_EXPIRY\\n"'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert active.stdout.readline().strip() == "STARTED"
            print("Waiting for the 30-second certificate to expire...", flush=True)
            while time.time() < state["expires_at_epoch"] + 0.2:
                time.sleep(0.2)
            evidence["new_authentication_after_expiry_rejected"] = (
                run(temporary_access(0) + ["true"], check=False).returncode != 0)
            def ssh_string(value):
                return struct.pack(">I", len(value)) + value
            body = (bytes([13]) + ssh_string(base64.b64decode(key_blob)) + ssh_string(b"expiry-probe")
                    + struct.pack(">I", 0))
            held_socket.sendall(struct.pack(">I", len(body)) + body)
            response = b""
            while len(response) < 5:
                chunk = held_socket.recv(5 - len(response))
                if not chunk:
                    break
                response += chunk
            evidence["already_connected_agent_client_denied_after_expiry"] = response == b"\x00\x00\x00\x01\x05"
            probe.terminate()
            probe.communicate(timeout=5)
            evidence["stopped_agent_socket_removed"] = not (grant / "agent.sock").exists()
            remainder, _ = active.communicate(timeout=8)
            evidence["existing_ssh_command_survived_expiry_and_agent_stop"] = remainder.strip() == "SURVIVED_EXPIRY"
            logs = run(["docker", "logs", containers[0]], check=False).stderr
            evidence["server_reported_expired_certificate"] = "Certificate invalid: expired" in logs
            print(json.dumps(evidence, indent=2), flush=True)
            checks = [value for key, value in evidence.items() if isinstance(value, bool)
                      and key != "biometric_policy_tested"]
            assert all(checks), "A protocol check failed"
            assert evidence["ca_signatures_for_multi_host_grant"] == 1
            assert evidence["temporary_agent_signatures"] >= 4
            print("PASS. Real Touch ID approval, launchd, lock/sleep and production CLI remain untested.", flush=True)
        finally:
            if held_socket:
                held_socket.close()
            if probe and probe.poll() is None:
                probe.terminate()
                probe.communicate(timeout=5)
            if active and active.poll() is None:
                active.terminate()
                active.communicate(timeout=5)
            for cid in containers:
                run(["docker", "rm", "-f", cid], check=False)


if __name__ == "__main__":
    verify()

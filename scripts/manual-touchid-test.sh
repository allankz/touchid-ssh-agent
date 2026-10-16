#!/bin/bash
# Manual Touch ID check, run under launchd like the installed agent.
#
# Part 1 creates a throwaway Touch ID identity in a temp directory, starts the
# agent as a temporary launchd job, then asks you to approve, refuse, ignore
# (the prompt must time out) and approve again (the agent must not be stuck).
#
# Part 2 (temporary access, needs Docker) enrolls a throwaway sshd container
# with a real Touch ID CA, issues grants through the per-grant launchd job and
# asks you to approve, refuse and ignore issuance. It checks repeated logins
# without prompts, the idle-sleep assertion, stop and cleanup.
# Nothing outside the temp directory and that container is touched.
#
# LAUNCH_ONLY=1 stops after checking that the launchd job serves the identity
# (no Touch ID needed). SKIP_ACCESS=1 skips part 2. The output is also saved
# to .build/test-touchid-last.log.
set -euo pipefail

RESULT_LOG="$(cd "$(dirname "$0")/.." && pwd)/.build/test-touchid-last.log"
mkdir -p "$(dirname "$RESULT_LOG")"
exec > >(tee "$RESULT_LOG") 2>&1
echo "make test-touchid — $(date '+%Y-%m-%d %H:%M:%S')"

BIN="$(cd "$(dirname "${1:-.build/release/touchid-ssh-agent}")" && pwd)/$(basename "${1:-.build/release/touchid-ssh-agent}")"
# /tmp keeps the grant socket paths under the 104-byte Unix socket limit.
DIR="$(mktemp -d /tmp/tidssh-manual-XXXXXX)"
CONTAINER=""
LABEL="local.touchid-ssh-agent.manual-test"
DOMAIN="gui/$(id -u)"
AGENT_DIR="$DIR/agent"
SOCK="$AGENT_DIR/agent.sock"
PUB="$AGENT_DIR/id_ecdsa_se.pub"

cleanup() {
    if [ -d "$AGENT_DIR/access" ]; then
        TOUCHID_SSH_AGENT_DIR="$AGENT_DIR" "$BIN" access stop --json >/dev/null 2>&1 || true
        TOUCHID_SSH_AGENT_DIR="$AGENT_DIR" "$BIN" access cleanup --json >/dev/null 2>&1 || true
    fi
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    if [ -n "$CONTAINER" ]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; fi
    rm -rf "$DIR"
}
trap cleanup EXIT

TOUCHID_SSH_AGENT_DIR="$AGENT_DIR" "$BIN" create --comment manual-test >/dev/null
echo "Temporary identity: $(TOUCHID_SSH_AGENT_DIR="$AGENT_DIR" "$BIN" fingerprint)"

cat > "$DIR/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$BIN</string><string>agent</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>TOUCHID_SSH_AGENT_DIR</key><string>$AGENT_DIR</string>
    <key>TOUCHID_SSH_AGENT_PROMPT_TIMEOUT</key><string>20</string>
  </dict>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardErrorPath</key><string>$DIR/stderr.log</string>
</dict></plist>
EOF
launchctl bootstrap "$DOMAIN" "$DIR/$LABEL.plist"
# macOS 26 may leave a freshly bootstrapped job as a pending "speculative"
# spawn that never runs; start it explicitly, as `touchid-ssh-agent install` does.
launchctl kickstart "$DOMAIN/$LABEL"
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
if [ ! -S "$SOCK" ]; then
    echo "the agent did not start"
    launchctl print "$DOMAIN/$LABEL" 2>&1 | grep -E "^\s+(state|last exit code|pended)" || true
    cat "$DIR/stderr.log" "$AGENT_DIR/agent.log" 2>/dev/null || true
    exit 1
fi

if [ "$(SSH_AUTH_SOCK="$SOCK" ssh-add -L 2>/dev/null)" != "$(cat "$PUB" | tr -d '\n')" ]; then
    echo "the agent started but does not offer the expected identity"
    exit 1
fi
echo "Agent running under launchd and offering the identity."
if [ "${LAUNCH_ONLY:-0}" = 1 ]; then exit 0; fi

echo
echo "Each prompt stays on screen for at most 20 s. Read the dialog text before acting."
read -r -p "Press Enter to start... " _ < /dev/tty

echo "test@local $(cat "$PUB")" > "$DIR/allowed_signers"
echo "test message" > "$DIR/msg"

# Prints sign | nosign | hung. A 60 s watchdog catches an agent that never answers.
sign() {
    rm -f "$DIR/msg.sig"
    local rc=0
    SSH_AUTH_SOCK="$SOCK" perl -e 'alarm shift; exec @ARGV' 60 \
        ssh-keygen -q -Y sign -f "$PUB" -n file "$DIR/msg" >/dev/null 2>&1 || rc=$?
    if [ "$rc" = 142 ]; then echo hung; return; fi
    if [ "$rc" = 0 ] && ssh-keygen -q -Y verify -f "$DIR/allowed_signers" -I test@local -n file \
            -s "$DIR/msg.sig" < "$DIR/msg" >/dev/null 2>&1; then
        echo sign
    else
        echo nosign
    fi
}

results=()
step() { # step "instruction" expected(sign|nosign)
    echo
    echo "$1"
    local start=$SECONDS outcome
    outcome=$(sign)
    local took=$((SECONDS - start))
    if [ "$outcome" = "$2" ]; then
        if [ "$2" = sign ]; then echo "    ✓ signature valid for OpenSSH (${took}s)"
        else echo "    ✓ no signature produced (${took}s)"; fi
        results+=(ok)
    else
        echo "    ✗ expected $2, got $outcome (${took}s)"
        results+=(failed)
    fi
}

step "1/9 — Touch the sensor to APPROVE." sign
step "2/9 — Click DENY." nosign
step "3/9 — Do NOTHING: the prompt must go away by itself within 20 s." nosign
step "4/9 — Touch the sensor to APPROVE again (the agent must not be stuck)." sign

echo
echo "Agent log:"
sed 's/^/    /' "$AGENT_DIR/agent.log"

finish() {
    echo
    if [[ " ${results[*]} " != *" failed "* ]]; then
        echo "RESULT: OK (${#results[@]}/${#results[@]})"
    else
        echo "RESULT: FAILED (${results[*]})"
        exit 1
    fi
}

if [ "${SKIP_ACCESS:-0}" = 1 ] || ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo
    echo "Temporary access part skipped (SKIP_ACCESS=1, or Docker is not available)."
    finish
fi

# ---- Part 2: temporary access with a real Touch ID CA and launchd grant jobs.
echo
echo "Part 2: temporary access. Starting a throwaway sshd container..."
REPO="$(cd "$(dirname "$0")/.." && pwd)"
docker build -q -t touchid-ssh-agent-e2e:local "$REPO/Tests/e2e" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C bootstrap -f "$DIR/bootstrap"
ssh-keygen -q -t ed25519 -N "" -C manual-emergency -f "$DIR/emergency"
CONTAINER="$(docker run -d --rm -p 127.0.0.1::22 -e "AUTHORIZED_KEYS=$(cat "$DIR/bootstrap.pub")" touchid-ssh-agent-e2e:local)"
PORT="$(docker port "$CONTAINER" 22/tcp | head -1 | cut -d: -f2)"
for _ in $(seq 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done
sleep 0.5
printf '%s\n' "Host e2e-manual" "  HostName 127.0.0.1" "  Port $PORT" "  User tester" \
    "  IdentityFile $DIR/bootstrap" "  IdentitiesOnly yes" "  IdentityAgent none" \
    "  StrictHostKeyChecking no" "  UserKnownHostsFile $DIR/known_hosts" "  LogLevel ERROR" > "$DIR/ssh_config"
export TOUCHID_SSH_AGENT_DIR="$AGENT_DIR" TOUCHID_SSH_AGENT_PROMPT_TIMEOUT=20 TOUCHID_SSH_AGENT_NO_REVEAL=1
"$BIN" recovery import "$DIR/emergency.pub" >/dev/null

# Prints the error code of a JSON result, or "ok".
code() { /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print("ok" if d.get("ok") else d["error"]["code"])' 2>/dev/null || echo none; }
check_step() { # check_step "description" status(0 = passed)
    if [ "$2" = 0 ]; then echo "    ✓ $1"; results+=(ok); else echo "    ✗ $1"; results+=(failed); fi
}

echo
echo "5/9 — authorize --temporary-access: APPROVE two prompts, the Touch ID login check"
echo "      and then the CA's validation certificate (\"check that a server accepts...\")."
rc=0
"$BIN" authorize e2e-manual -F "$DIR/ssh_config" --alias manual --temporary-access > "$DIR/authorize.out" 2>&1 || rc=$?
grep -E "✓|✗" "$DIR/authorize.out" | sed 's/^/    /' || true
check_step "server enrolled with the Touch ID CA (current-set)" "$rc"

echo
echo "6/9 — access: APPROVE the prompt \"allow temporary SSH access to 1 target...\"."
"$BIN" access manual --for 2m --json > "$DIR/grant.json" 2> "$DIR/grant.err" || true
granted="$(code < "$DIR/grant.json")"
check_step "grant issued by the launchd job ($granted)" "$([ "$granted" = ok ] && echo 0 || echo 1)"
CONFIG="$(/usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["ssh_config_path"])' < "$DIR/grant.json" 2>/dev/null || true)"
ALIAS="$(/usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["targets"][0]["ssh_alias"])' < "$DIR/grant.json" 2>/dev/null || true)"
echo "      Three logins follow; no Touch ID prompt may appear."
logins=0
for n in 1 2 3; do
    if ssh -F "$CONFIG" "$ALIAS" "echo login-$n" 2>/dev/null | grep -q "login-$n"; then logins=$((logins + 1)); fi
done
check_step "3 logins without prompts" "$([ "$logins" = 3 ] && echo 0 || echo 1)"
held=1; pmset -g assertions | grep -q "touchid-ssh-agent temporary SSH access" && held=0
check_step "idle-sleep assertion held while the grant is active" "$held"
"$BIN" access stop --json >/dev/null 2>&1 || true
sleep 1
released=0; pmset -g assertions | grep -q "touchid-ssh-agent temporary SSH access" && released=1
check_step "stop released the assertion" "$released"
refused=0; ssh -F "$CONFIG" "$ALIAS" true 2>/dev/null && refused=1
check_step "the old command fails after stop" "$refused"

echo
echo "7/9 — access: click DENY."
"$BIN" access manual --for 2m --json > "$DIR/denied.json" 2>/dev/null || true
denied="$(code < "$DIR/denied.json")"
check_step "denied: $denied" "$([ "$denied" = approval_denied ] && echo 0 || echo 1)"

echo
echo "8/9 — access: do NOTHING; the prompt must go away by itself within 20 s."
"$BIN" access manual --for 2m --json > "$DIR/timeout.json" 2>/dev/null || true
timedout="$(code < "$DIR/timeout.json")"
check_step "timed out: $timedout" "$([ "$timedout" = approval_timeout ] && echo 0 || echo 1)"

echo
echo "9/9 — nothing left behind"
left="$( (ls "$AGENT_DIR/access/grants" 2>/dev/null || true) | wc -l | tr -d ' ')"
check_step "no grant directory left ($left)" "$([ "$left" = 0 ] && echo 0 || echo 1)"
running="$(launchctl list | awk '$1 != "-" && $3 ~ /local.touchid-ssh-agent.access./' | wc -l | tr -d ' ')"
check_step "no grant job running ($running)" "$([ "$running" = 0 ] && echo 0 || echo 1)"

echo
echo "Access log:"
sed 's/^/    /' "$AGENT_DIR/access.log" 2>/dev/null || true
finish

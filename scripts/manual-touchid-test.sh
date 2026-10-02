#!/bin/bash
# Manual Touch ID check, run under launchd like the installed agent.
#
# Creates a throwaway Touch ID identity in a temp directory, starts the agent
# as a temporary launchd job, then asks you to approve, refuse, ignore (the
# prompt must time out) and approve again (the agent must not stay stuck).
# Nothing outside the temp directory is touched.
#
# LAUNCH_ONLY=1 stops after checking that the launchd job serves the identity
# (no Touch ID needed). The output is also saved to .build/test-touchid-last.log.
set -euo pipefail

RESULT_LOG="$(cd "$(dirname "$0")/.." && pwd)/.build/test-touchid-last.log"
mkdir -p "$(dirname "$RESULT_LOG")"
exec > >(tee "$RESULT_LOG") 2>&1
echo "make test-touchid — $(date '+%Y-%m-%d %H:%M:%S')"

BIN="$(cd "$(dirname "${1:-.build/release/touchid-ssh-agent}")" && pwd)/$(basename "${1:-.build/release/touchid-ssh-agent}")"
TMP="${TMPDIR:-/tmp}"
DIR="$(mktemp -d "${TMP%/}/tidssh-manual-XXXXXX")"
LABEL="local.touchid-ssh-agent.manual-test"
DOMAIN="gui/$(id -u)"
AGENT_DIR="$DIR/agent"
SOCK="$AGENT_DIR/agent.sock"
PUB="$AGENT_DIR/id_ecdsa_se.pub"

cleanup() {
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
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

step "1/4 — Touch the sensor to APPROVE." sign
step "2/4 — Click DENY." nosign
step "3/4 — Do NOTHING: the prompt must go away by itself within 20 s." nosign
step "4/4 — Touch the sensor to APPROVE again (the agent must not be stuck)." sign

echo
echo "Agent log:"
sed 's/^/    /' "$AGENT_DIR/agent.log"

echo
if [[ " ${results[*]} " != *" failed "* ]]; then
    echo "RESULT: OK (4/4)"
else
    echo "RESULT: FAILED (${results[*]})"
    exit 1
fi

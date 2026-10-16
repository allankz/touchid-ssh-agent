#!/bin/sh
set -eu
install -d -m 700 -o tester -g tester /home/tester/.ssh
printf '%s\n' "${AUTHORIZED_KEYS:?}" > /home/tester/.ssh/authorized_keys
chown tester:tester /home/tester/.ssh/authorized_keys
chmod 600 /home/tester/.ssh/authorized_keys
# Optional extra sshd settings for a test, e.g. refusing certificates.
if [ -n "${SSHD_EXTRA:-}" ]; then printf '%s\n' "$SSHD_EXTRA" > /etc/ssh/sshd_config.d/zz-test.conf; fi
exec /usr/sbin/sshd -D -e

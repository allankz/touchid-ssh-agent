# Throwaway OpenSSH server for the end-to-end test. Only public-key
# authentication is enabled; the authorized keys come from $AUTHORIZED_KEYS.
FROM alpine:3.22

RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh tester \
 && sed -i 's/^tester:!/tester:*/' /etc/shadow \
 && printf '%s\n' \
      'PasswordAuthentication no' \
      'KbdInteractiveAuthentication no' \
      'PubkeyAuthentication yes' \
      'PermitRootLogin no' \
      'AllowUsers tester' \
      'LogLevel VERBOSE' > /etc/ssh/sshd_config.d/e2e.conf

COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]

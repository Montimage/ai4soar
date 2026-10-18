# Throwaway SSH host for demo runs, touching no real machine:
#  - SOARCA dry runs echo each command here (from the soarca network)
#  - Shuffle runs the demo firewall step here (sudo iptables, in this container's own
#    network namespace only), reaching it at the docker host address 172.17.0.1:2223
FROM alpine:3.20
ARG SANDBOX_PASSWORD
RUN apk add --no-cache openssh bash coreutils iptables sudo \
 && ssh-keygen -A \
 && adduser -D -s /bin/bash ai4soar \
 && echo "ai4soar:${SANDBOX_PASSWORD}" | chpasswd \
 && echo 'ai4soar ALL=(root) NOPASSWD: /sbin/iptables, /usr/sbin/iptables' > /etc/sudoers.d/ai4soar \
 && chmod 440 /etc/sudoers.d/ai4soar \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

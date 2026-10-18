#!/bin/sh
# The services the playbooks expect on a server: cron and at (scheduled rule removal), sshd
cron
atd
postfix start 2>/dev/null
# The saved firewall ruleset a server restores at boot (empty: accept all)
iptables-save > /etc/iptables/rules.v4
# Something to investigate, as in the demo alerts: a "malicious" script and the XMRig
# cryptominer (a renamed sleep, restarted by dev's crontab), both running as dev
su - dev -c 'nohup /tmp/payload.sh > /dev/null 2>&1 &'
su - dev -c 'nohup /tmp/.cache/xmrig 100000 > /dev/null 2>&1 &'
su - dev -c 'nohup sleep 100000 > /dev/null 2>&1 &'
mkdir -p /var/log && touch /var/log/auth.log
exec /usr/sbin/sshd -D -e

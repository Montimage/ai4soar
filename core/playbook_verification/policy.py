"""
Response-action safety policy for SOAR playbooks.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence


@dataclass(frozen=True)
class PolicyRule:
    """One safety rule.

    name    stable identifier, reported in metrics and audit output
    pattern matched against a single command string
    why     one line explaining the risk, shown in reports
    """

    name: str
    pattern: "re.Pattern"
    why: str


POLICY_RULES: Sequence[PolicyRule] = (
    PolicyRule("recursive_delete",
               re.compile(r"\brm\s+(-\w*\s+)*-\w*[rR]\w*f|\brm\s+-\w*f\w*[rR]", re.I),
               "recursive forced delete"),
    PolicyRule("disk_write",
               re.compile(r"\b(dd|mkfs(\.\w+)?|fdisk|shred)\b", re.I),
               "destroys data on a device"),
    PolicyRule("host_shutdown",
               re.compile(r"\b(shutdown|reboot|halt|poweroff|init\s+0)\b", re.I),
               "takes the host offline"),
    PolicyRule("flush_firewall",
               re.compile(r"\biptables\s+(-\w+\s+)*-[FXZ]\b|\bnft\s+flush\b", re.I),
               "clears ALL firewall rules, not just the offender"),
    PolicyRule("unscoped_drop",
               re.compile(r"iptables[^\n|;&]*-j\s+DROP", re.I),
               "DROP with no -s/-d/--dport restriction blocks everything"),
    PolicyRule("broad_kill",
               re.compile(r"\b(pkill|killall)\b|\bkill\s+-9\s+-1\b", re.I),
               "kills processes by name, not by verified pid"),
    PolicyRule("permissive_chmod",
               re.compile(r"\bchmod\s+(-\w+\s+)*777\b", re.I),
               "world-writable permissions"),
    # Must distinguish destroying a log from WRITING evidence into /var/log. An earlier
    # version matched any `> /var/log/...` and flagged
    # `... > /var/log/ir/<case>/auth_events.txt` — an evidence-preservation step — as
    # evidence destruction. Only truncation/removal, or redirection over a KNOWN system
    # log, counts.
    PolicyRule("log_destruction",
               re.compile(
                   r"\b(?:truncate\s+-s\s*0|shred\b[^\n;|]*?|rm\s+(?:-\w+\s+)*)\s*/var/log/"
                   r"|:\s*>\s*/var/log/"
                   r"|/dev/null\s*>\s*/var/log/"
                   r"|>\s*/var/log/(?:auth\.log|secure|syslog|messages|wtmp|btmp|lastlog|audit)"
                   r"|\bhistory\s+-c\b", re.I),
               "destroys log evidence"),
    PolicyRule("curl_pipe_shell",
               re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b", re.I),
               "executes remote code"),
)

_DROP_SCOPED = re.compile(r"-s\s|\s-d\s|--dport|--sport|-p\s+tcp", re.I)


def policy_violations(cmd: str) -> List[str]:
    """Rule names this command trips, in ruleset order.
    """
    hits = [rule.name for rule in POLICY_RULES if rule.pattern.search(cmd)]
    if "unscoped_drop" in hits and _DROP_SCOPED.search(cmd):
        hits.remove("unscoped_drop")
    return hits


def describe(name: str) -> Optional[str]:
    """The `why` for a rule name, or None if the name is not in the ruleset."""
    for rule in POLICY_RULES:
        if rule.name == name:
            return rule.why
    return None

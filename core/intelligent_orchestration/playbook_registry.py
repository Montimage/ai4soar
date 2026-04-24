"""
Tactic registry — maps MITRE TA-codes to ATT&CK phase names.

M-code content removed: operational response is now handled by the CACAO
PlaybookLibrary in core/playbook_library/.
"""

from typing import Dict

# TA-code → ATT&CK kill_chain phase_name (matches STIX kill_chain_phases)
TACTIC_TA_TO_NAME: Dict[str, str] = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
    "TA0042": "resource-development",
    "TA0043": "reconnaissance",
}


def ta_code_to_name(ta_code: str) -> str:
    """Convert TA-code (e.g. 'TA0006') → phase_name (e.g. 'credential-access')."""
    return TACTIC_TA_TO_NAME.get(ta_code, "unknown")

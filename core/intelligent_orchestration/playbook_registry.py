"""
Playbook name registry for AI4SOAR.

Maps MITRE ATT&CK:
  - Tactic phase_names → default playbook names (when only tactic is known)
  - Mitigation M-codes → specific Shuffle playbook names

Playbook names defined here are the canonical names used in Shuffle SOAR.
Add entries here as you create real playbooks in Shuffle.
"""

from typing import Dict, List

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

# M-code → Shuffle playbook name
# Extend as you build actual playbooks in Shuffle SOAR
MITIGATION_TO_PLAYBOOK: Dict[str, str] = {
    "M1036": "PB_Account_Lockout_Policy",
    "M1032": "PB_MFA_Enforcement",
    "M1027": "PB_Password_Policy_Enforcement",
    "M1026": "PB_Privileged_Account_Containment",
    "M1051": "PB_Patch_and_Update_Software",
    "M1018": "PB_User_Account_Investigation",
    "M1042": "PB_Service_Disable_Response",
    "M1017": "PB_User_Training_Alert",
    "M1030": "PB_Network_Segmentation",
    "M1037": "PB_Traffic_Filter_Response",
    "M1031": "PB_Network_Intrusion_Prevention",
    "M1049": "PB_Antivirus_Scan",
    "M1038": "PB_Execution_Prevention",
    "M1045": "PB_Code_Signing_Enforcement",
    "M1022": "PB_File_Permission_Hardening",
    "M1024": "PB_OS_Configuration_Hardening",
    "M1019": "PB_Threat_Intelligence_Feed",
    "M1054": "PB_Software_Configuration_Review",
    "M1047": "PB_Audit_and_Inventory",
    "M1033": "PB_Limit_Software_Installation",
    "M1034": "PB_Limit_Hardware_Installation",
    "M1028": "PB_OS_Configuration_Hardening",
    "M1025": "PB_Privileged_Process_Integrity",
    "M1050": "PB_Exploit_Protection",
    "M1053": "PB_Data_Backup",
    "M1057": "PB_Data_Loss_Prevention",
    "M1043": "PB_Credential_Access_Protection",
    "M1041": "PB_Encrypt_Sensitive_Information",
    "M1040": "PB_Behavior_Prevention_on_Endpoint",
    "M1039": "PB_Environment_Variable_Permission",
}

# Tactic phase_name → ordered list of playbook names (most relevant first)
# Used as fallback when only the tactic is predicted (not the specific technique)
TACTIC_TO_PLAYBOOKS: Dict[str, List[str]] = {
    "credential-access": [
        "PB_Account_Lockout_Policy",
        "PB_MFA_Enforcement",
        "PB_Password_Policy_Enforcement",
        "PB_Privileged_Account_Containment",
        "PB_Credential_Access_Protection",
    ],
    "lateral-movement": [
        "PB_Network_Segmentation",
        "PB_Privileged_Account_Containment",
        "PB_Traffic_Filter_Response",
        "PB_MFA_Enforcement",
        "PB_User_Account_Investigation",
    ],
    "initial-access": [
        "PB_Network_Intrusion_Prevention",
        "PB_Traffic_Filter_Response",
        "PB_Patch_and_Update_Software",
        "PB_Exploit_Protection",
    ],
    "execution": [
        "PB_Execution_Prevention",
        "PB_Antivirus_Scan",
        "PB_Service_Disable_Response",
        "PB_Behavior_Prevention_on_Endpoint",
    ],
    "persistence": [
        "PB_User_Account_Investigation",
        "PB_Audit_and_Inventory",
        "PB_Service_Disable_Response",
        "PB_OS_Configuration_Hardening",
    ],
    "privilege-escalation": [
        "PB_Privileged_Account_Containment",
        "PB_OS_Configuration_Hardening",
        "PB_File_Permission_Hardening",
        "PB_Privileged_Process_Integrity",
    ],
    "defense-evasion": [
        "PB_Audit_and_Inventory",
        "PB_Code_Signing_Enforcement",
        "PB_Software_Configuration_Review",
        "PB_Behavior_Prevention_on_Endpoint",
    ],
    "discovery": [
        "PB_Network_Segmentation",
        "PB_Traffic_Filter_Response",
        "PB_Audit_and_Inventory",
        "PB_Network_Intrusion_Prevention",
    ],
    "collection": [
        "PB_File_Permission_Hardening",
        "PB_Network_Segmentation",
        "PB_Audit_and_Inventory",
        "PB_Data_Loss_Prevention",
    ],
    "exfiltration": [
        "PB_Network_Segmentation",
        "PB_Traffic_Filter_Response",
        "PB_Network_Intrusion_Prevention",
        "PB_Data_Loss_Prevention",
        "PB_Encrypt_Sensitive_Information",
    ],
    "command-and-control": [
        "PB_Traffic_Filter_Response",
        "PB_Network_Intrusion_Prevention",
        "PB_Network_Segmentation",
    ],
    "impact": [
        "PB_Patch_and_Update_Software",
        "PB_Service_Disable_Response",
        "PB_Antivirus_Scan",
        "PB_Data_Backup",
    ],
    "resource-development": [
        "PB_Threat_Intelligence_Feed",
    ],
    "reconnaissance": [
        "PB_Network_Intrusion_Prevention",
        "PB_Traffic_Filter_Response",
    ],
}


def ta_code_to_name(ta_code: str) -> str:
    """Convert TA-code (e.g. 'TA0006') → phase_name (e.g. 'credential-access')."""
    return TACTIC_TA_TO_NAME.get(ta_code, "unknown")


def get_playbooks_for_tactic(tactic: str) -> List[Dict]:
    """
    Return playbook dicts for a tactic phase_name.
    Format mirrors STIX mitigation dicts for API consistency.
    """
    names = TACTIC_TO_PLAYBOOKS.get(tactic, [])
    return [{"id": name, "name": name, "description": f"Playbook for {tactic}"} for name in names]


def get_playbook_for_mitigation(mitigation_id: str) -> str:
    """Return Shuffle playbook name for a MITRE mitigation M-code."""
    return MITIGATION_TO_PLAYBOOK.get(mitigation_id, f"PB_{mitigation_id}")


# Type hint for playbook dict (used in recommendation_service)
PlaybookDict = Dict[str, str]

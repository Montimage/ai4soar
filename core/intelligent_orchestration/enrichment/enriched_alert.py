"""
EnrichedAlert — the canonical alert representation after the Enrichment Layer.

All downstream components (Path A/B/C/D, Decision Engine) receive an EnrichedAlert
instead of the raw alert dict. This centralises extraction and keeps paths clean.

Current fields are intentionally minimal (normalize + MITRE extract).
Future additions (asset criticality, IP reputation, correlation context) belong here.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class EnrichedAlert:
    """Alert after the enrichment pipeline has been applied."""

    # Original alert — passed to components that need format-specific fields
    # (e.g. STIX KB lookup, ML normalizer).
    raw: Dict[str, Any]

    # MITRE ATT&CK fields extracted by the Enrichment Layer.
    # Non-empty → Stage 1 (Path A) is eligible.
    technique_ids: List[str]    # e.g. ["T1021.002"]
    technique_names: List[str]  # e.g. ["SMB/Windows Admin Shares"]
    tactics: List[str]          # e.g. ["lateral-movement"]

    # Detected source format — useful for logging and future per-format enrichers.
    source_format: str          # "wazuh" | "ecs" | "sigma" | "generic"

    # -----------------------------------------------------------------------
    # Future enrichment fields (add here when the Enrichment Layer expands)
    # -----------------------------------------------------------------------
    # asset_criticality: str = ""      # "critical" | "high" | "medium" | "low"
    # ip_reputation: Dict = field(default_factory=dict)
    # user_role: str = ""
    # correlated_alert_ids: List[str] = field(default_factory=list)
    # off_hours: bool = False

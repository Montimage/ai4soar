"""
Enrichment Pipeline — Stage 0 before any recommendation path runs.

Current scope (intentionally minimal):
  • Normalize alert format to a common structure
  • Extract explicit MITRE ATT&CK tags (technique IDs, names, tactics)
  • Detect source format for logging / future per-format enrichers

Extension points (add new enrichers here when ready):
  • Asset criticality lookup  (EnrichedAlert.asset_criticality)
  • IP reputation / geo       (EnrichedAlert.ip_reputation)
  • User role                 (EnrichedAlert.user_role)
  • Temporal context          (EnrichedAlert.off_hours)
  • Alert correlation         (EnrichedAlert.correlated_alert_ids)
  • Lightweight rule-based MITRE inference (before calling the LLM)
"""

import logging
from typing import Any, Dict

from core.intelligent_orchestration.stix_knowledge_base import (
    extract_mitre_ids,
    extract_mitre_technique_names,
    extract_mitre_tactics,
)
from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.intelligent_orchestration.enrichment.adapters import ADAPTERS

logger = logging.getLogger(__name__)


class EnrichmentPipeline:
    """
    Transforms a raw alert dict into an EnrichedAlert.

    Stage 0a — Adapter: detect the alert's source format and normalize it
                        to the canonical Wazuh-like _source envelope.
    Stage 0b — MITRE extraction: pull technique IDs / names / tactics from
                                  the normalized envelope.

    Stateless — safe to call from multiple threads.
    """

    def enrich(self, alert: Dict[str, Any]) -> EnrichedAlert:
        normalized, source_format = normalize_alert(alert)

        technique_ids   = extract_mitre_ids(normalized)
        technique_names = extract_mitre_technique_names(normalized)
        tactics         = extract_mitre_tactics(normalized)

        enriched = EnrichedAlert(
            raw=normalized,
            technique_ids=technique_ids,
            technique_names=technique_names,
            tactics=tactics,
            source_format=source_format,
        )

        logger.debug(
            f"[Enrichment] format={source_format} "
            f"techniques={technique_ids} tactics={tactics}"
        )
        return enriched


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def normalize_alert(alert: Dict[str, Any]):
    """
    Run the adapter chain.  Returns (normalized_alert, source_format).
    Falls back to the original alert + heuristic format detection if no
    adapter matches.
    """
    for adapter in ADAPTERS:
        try:
            if adapter.can_handle(alert):
                normalized = adapter.normalize(alert)
                return normalized, adapter.name
        except Exception as exc:
            logger.debug(f"[Adapter] {adapter.name} raised: {exc}")
            continue

    # No adapter matched — pass through unchanged with heuristic format tag.
    return alert, _detect_format(alert)


def _detect_format(alert: Dict) -> str:
    """Heuristic fallback format detection."""
    if "_source" in alert:
        src = alert["_source"]
        if "rule" in src and "mitre" in src.get("rule", {}):
            return "wazuh"
        if "rule" in src:
            return "wazuh_generic"
    if "threat" in alert and "technique" in alert.get("threat", {}):
        return "ecs"
    if "Techniques" in alert or "Tactics" in alert:
        return "sentinel"
    if "tags" in alert and any(
        str(t).startswith("attack.") for t in alert.get("tags", [])
    ):
        return "sigma"
    return "generic"

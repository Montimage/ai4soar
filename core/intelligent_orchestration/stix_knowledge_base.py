"""
MITRE ATT&CK STIX Knowledge Base — technique metadata only.

Parses the enterprise-attack STIX bundle and indexes techniques by
external ID (T-code) and name. Used for technique metadata lookup and
name resolution (e.g. by the enrichment pipeline).

Mitigation (M-code) content has been removed — operational response is
now handled by the CACAO PlaybookLibrary (core/playbook_library/).
"""

import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class STIXKnowledgeBase:
    """
    Loads and indexes MITRE ATT&CK technique metadata from a STIX bundle.

    Builds two indices:
      - technique_id  → technique metadata dict  (e.g. "T1110.001" → {...})
      - technique_name → technique_id             (e.g. "password guessing" → "T1110.001")
    """

    def __init__(self, stix_path: str):
        self.stix_path = stix_path
        self._techniques: Dict[str, Dict] = {}       # T-code → metadata
        self._name_to_id: Dict[str, str]  = {}       # lowercase name → T-code
        self._loaded = False

    # Compact bundled index — committed to the repo, no external dependency
    _BUNDLED_INDEX = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "data", "mitre_techniques.json"
    )

    def load(self) -> None:
        """Build technique indices. Idempotent.

        Priority:
          1. Full STIX bundle (STIX_DATA_PATH) — rich metadata, optional.
          2. Bundled compact index (data/mitre_techniques.json) — always present.
        """
        if self._loaded:
            return

        if os.path.exists(self.stix_path):
            self._load_from_stix()
        else:
            if self.stix_path:
                logger.debug(
                    f"Full STIX bundle not found at '{self.stix_path}'; "
                    "falling back to bundled compact index."
                )
            self._load_from_bundled()

        self._loaded = True

    def _load_from_stix(self) -> None:
        logger.info(f"Loading STIX knowledge base from {self.stix_path} …")
        with open(self.stix_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue
            ext_id = self._get_external_id(obj)
            if not ext_id:
                continue
            tech = {
                "technique_id":  ext_id,
                "name":          obj.get("name", ""),
                "description":   obj.get("description", ""),
                "tactics": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms":       obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
            self._techniques[ext_id] = tech
            self._name_to_id[tech["name"].lower()] = ext_id
        logger.info(f"STIX KB: {len(self._techniques)} techniques loaded from bundle")

    def _load_from_bundled(self) -> None:
        bundled = os.path.normpath(self._BUNDLED_INDEX)
        if not os.path.exists(bundled):
            logger.warning("Bundled MITRE index not found; technique lookup disabled.")
            return
        with open(bundled, "r", encoding="utf-8") as f:
            mapping: Dict[str, str] = json.load(f)
        for tid, name in mapping.items():
            self._techniques[tid] = {"technique_id": tid, "name": name, "tactics": [], "description": ""}
            self._name_to_id[name.lower()] = tid
        logger.info(f"STIX KB: {len(self._techniques)} techniques loaded from bundled index")

    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Return metadata for a technique ID, or None if not found."""
        self.load()
        return self._techniques.get(technique_id)

    def resolve_technique_name(self, name: str) -> Optional[str]:
        """Resolve a technique name to its T-code (case-insensitive)."""
        self.load()
        return self._name_to_id.get(name.lower())

    def stats(self) -> Dict:
        self.load()
        return {"total_techniques": len(self._techniques)}

    @staticmethod
    def _get_external_id(obj: Dict) -> Optional[str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None


# ------------------------------------------------------------------
# Module-level alert field extractors (used by the enrichment pipeline)
# ------------------------------------------------------------------

def extract_mitre_ids(alert: Dict) -> List[str]:
    """Extract MITRE technique IDs from a Wazuh alert dict."""
    mitre = (
        alert.get("_source", {})
             .get("rule", {})
             .get("mitre", {})
    )
    return mitre.get("id", [])


def extract_mitre_technique_names(alert: Dict) -> List[str]:
    """Extract MITRE technique names from a Wazuh alert dict."""
    mitre = (
        alert.get("_source", {})
             .get("rule", {})
             .get("mitre", {})
    )
    return mitre.get("technique", [])


def extract_mitre_tactics(alert: Dict) -> List[str]:
    """Extract MITRE tactic names from a Wazuh alert dict."""
    mitre = (
        alert.get("_source", {})
             .get("rule", {})
             .get("mitre", {})
    )
    return mitre.get("tactic", [])

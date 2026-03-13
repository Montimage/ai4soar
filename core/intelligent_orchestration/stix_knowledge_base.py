"""
MITRE ATT&CK STIX Knowledge Base for AI4SOAR.

Parses the enterprise-attack STIX bundle and builds a technique→mitigation
index used as ground-truth playbook labels.
"""

import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class STIXKnowledgeBase:
    """
    Loads and indexes the MITRE ATT&CK STIX bundle.

    Builds two primary indices:
      - technique_id  → list of mitigation dicts  (e.g. "T1110.001" → [...])
      - technique_name → technique_id              (e.g. "Password Guessing" → "T1110.001")

    The knowledge base is loaded lazily on first query and cached in memory.
    """

    def __init__(self, stix_path: str):
        self.stix_path = stix_path
        # technique external_id (T-code) → list of mitigation dicts
        self._tech_to_mitigations: Dict[str, List[Dict]] = {}
        # lowercase technique name → external_id
        self._name_to_id: Dict[str, str] = {}
        # external_id → technique metadata
        self._techniques: Dict[str, Dict] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Parse the STIX bundle and build all indices. Idempotent."""
        if self._loaded:
            return

        if not os.path.exists(self.stix_path):
            raise FileNotFoundError(
                f"STIX data file not found: {self.stix_path}. "
                "Set STIX_DATA_PATH in your .env or verify the path."
            )

        logger.info(f"Loading STIX knowledge base from {self.stix_path} ...")
        with open(self.stix_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        logger.info(f"STIX bundle contains {len(objects)} objects")

        # Index attack-patterns by STIX id and by external T-code
        stix_id_to_technique: Dict[str, Dict] = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue
            ext_id = self._get_external_id(obj)
            if not ext_id:
                continue
            tech = {
                "stix_id": obj["id"],
                "technique_id": ext_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
            stix_id_to_technique[obj["id"]] = tech
            self._techniques[ext_id] = tech
            self._name_to_id[obj.get("name", "").lower()] = ext_id

        logger.info(f"Indexed {len(self._techniques)} active techniques")

        # Index course-of-action (mitigations) by STIX id
        stix_id_to_mitigation: Dict[str, Dict] = {}
        for obj in objects:
            if obj.get("type") != "course-of-action":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue
            ext_id = self._get_external_id(obj)
            stix_id_to_mitigation[obj["id"]] = {
                "id": ext_id or obj["id"],
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }

        logger.info(f"Indexed {len(stix_id_to_mitigation)} active mitigations")

        # Build technique → mitigations map via "mitigates" relationships
        # Direction: source_ref=course-of-action  →  target_ref=attack-pattern
        mitigates_count = 0
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "mitigates":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue

            mitigation = stix_id_to_mitigation.get(obj.get("source_ref"))
            technique_stix = stix_id_to_technique.get(obj.get("target_ref"))
            if not mitigation or not technique_stix:
                continue

            tech_id = technique_stix["technique_id"]
            if tech_id not in self._tech_to_mitigations:
                self._tech_to_mitigations[tech_id] = []
            # avoid duplicates (multiple relationship revisions)
            if not any(m["id"] == mitigation["id"]
                       for m in self._tech_to_mitigations[tech_id]):
                self._tech_to_mitigations[tech_id].append(mitigation)
                mitigates_count += 1

        techniques_with_mitigations = len(self._tech_to_mitigations)
        logger.info(
            f"Built technique→mitigation index: "
            f"{techniques_with_mitigations} techniques covered, "
            f"{mitigates_count} links total"
        )
        self._loaded = True

    def get_playbooks_for_technique(self, technique_id: str) -> List[Dict]:
        """
        Return all mitigations (playbook names) for a given technique ID.

        Args:
            technique_id: MITRE technique ID, e.g. "T1110.001" or "T1110"

        Returns:
            List of dicts: [{"id": "M1036", "name": "...", "description": "..."}]
            Empty list if technique has no mitigations or is unknown.
        """
        self.load()
        return list(self._tech_to_mitigations.get(technique_id, []))

    def get_playbooks_for_alert(self, alert: Dict) -> List[Dict]:
        """
        Return deduplicated mitigations for all MITRE technique IDs in an alert.

        Reads alert["_source"]["rule"]["mitre"]["id"] — the standard Wazuh field.
        Falls back to name-based lookup if IDs are missing.

        Args:
            alert: Wazuh alert dict (full ES document format)

        Returns:
            List of unique mitigation dicts ordered by technique ID then name.
        """
        self.load()
        technique_ids = extract_mitre_ids(alert)

        # Fallback: resolve technique names to IDs if IDs are absent
        if not technique_ids:
            names = extract_mitre_technique_names(alert)
            technique_ids = [
                self._name_to_id[n.lower()]
                for n in names
                if n.lower() in self._name_to_id
            ]

        seen_ids: set = set()
        result: List[Dict] = []
        for tech_id in technique_ids:
            for mitigation in self.get_playbooks_for_technique(tech_id):
                if mitigation["id"] not in seen_ids:
                    seen_ids.add(mitigation["id"])
                    result.append(mitigation)

        return result

    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Return metadata for a technique ID, or None if not found."""
        self.load()
        return self._techniques.get(technique_id)

    def resolve_technique_name(self, name: str) -> Optional[str]:
        """Resolve a technique name to its ID (case-insensitive)."""
        self.load()
        return self._name_to_id.get(name.lower())

    def stats(self) -> Dict:
        """Return summary statistics about the loaded knowledge base."""
        self.load()
        return {
            "total_techniques": len(self._techniques),
            "techniques_with_mitigations": len(self._tech_to_mitigations),
            "total_mitigation_links": sum(
                len(v) for v in self._tech_to_mitigations.values()
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_external_id(obj: Dict) -> Optional[str]:
        """Extract the MITRE external ID (T-code or M-code) from an object."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None


# ------------------------------------------------------------------
# Module-level alert field extractors (used by other modules too)
# ------------------------------------------------------------------

def extract_mitre_ids(alert: Dict) -> List[str]:
    """
    Extract MITRE technique IDs (e.g. ["T1110.001", "T1021.004"]) from a
    Wazuh alert dict.
    """
    mitre = (
        alert.get("_source", {})
             .get("rule", {})
             .get("mitre", {})
    )
    return mitre.get("id", [])


def extract_mitre_technique_names(alert: Dict) -> List[str]:
    """
    Extract MITRE technique names (e.g. ["Password Guessing", "SSH"]) from a
    Wazuh alert dict.
    """
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

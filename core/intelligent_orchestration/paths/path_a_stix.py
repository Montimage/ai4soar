"""
Path A — Direct Playbook Lookup (Gold Standard).

Input:  EnrichedAlert with non-empty technique_ids
Output: PathResult (confidence = 1.0, never None)

Looks up the technique IDs in the PlaybookLibrary, extracts IOCs from the
alert, and returns parameterized CACAO playbooks ready for execution.
The Orchestrator calls this only when enriched.technique_ids is non-empty.
"""

import logging

from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.intelligent_orchestration.enrichment.ioc_extractor import IOCExtractor
from core.intelligent_orchestration.parameterizer import PlaybookParameterizer
from core.intelligent_orchestration.path_result import PathResult
from core.playbook_library.loader import PlaybookLibrary

logger = logging.getLogger(__name__)


def _matches(template, alert) -> bool:
    """template alert_match {rule_ids: [...], groups: [...]} against the alert's rule."""
    spec = (template or {}).get("alert_match") or {}
    if not spec:
        return False
    rule = ((alert or {}).get("_source") or alert or {}).get("rule") or {}
    if str(rule.get("id", "")) in {str(r) for r in spec.get("rule_ids") or []}:
        return True
    return bool(set(rule.get("groups") or []) & set(spec.get("groups") or []))


class PathARecommender:

    def __init__(
        self,
        library:      PlaybookLibrary,
        ioc_extractor: IOCExtractor,
        parameterizer: PlaybookParameterizer,
    ) -> None:
        self._library      = library
        self._ioc_extractor = ioc_extractor
        self._parameterizer = parameterizer

    def run(self, enriched: EnrichedAlert, k: int) -> PathResult:
        """
        Look up CACAO templates for known technique IDs, inject alert IOCs.

        Returns PathResult with confidence=1.0.
        The Orchestrator checks whether playbooks is non-empty to decide
        if the early exit applies.
        """
        iocs     = self._ioc_extractor.extract(enriched.raw)
        playbooks = []
        seen: set = set()
        templates = {}

        for tid in enriched.technique_ids:
            for template in self._library.get_for_technique(tid):
                if template["id"] not in seen:
                    seen.add(template["id"])
                    templates[template["id"]] = template
                    pb = self._parameterizer.parameterize(template, iocs, enriched.raw)
                    playbooks.append(pb.to_dict())

        # A template declaring this exact alert (alert_match: Wazuh rule id or alert group)
        # is the tested response for it: recommended alone, ahead of the technique match
        exact = [pb for pb in playbooks if _matches(templates[pb["id"]], enriched.raw)]
        if exact:
            playbooks = exact
        playbooks = playbooks[:k]
        logger.info(f"[Path A] {enriched.technique_ids} → {len(playbooks)} CACAO playbooks"
                    + (" (exact alert match)" if exact else ""))

        return PathResult(
            playbooks=playbooks,
            source="playbook_library_direct",
            confidence=1.0,
            technique_ids=enriched.technique_ids,
            technique_names=enriched.technique_names,
            tactics=enriched.tactics,
        )

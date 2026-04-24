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

        for tid in enriched.technique_ids:
            for template in self._library.get_for_technique(tid):
                if template["id"] not in seen:
                    seen.add(template["id"])
                    pb = self._parameterizer.parameterize(template, iocs, enriched.raw)
                    playbooks.append(pb.to_dict())

        playbooks = playbooks[:k]
        logger.info(f"[Path A] {enriched.technique_ids} → {len(playbooks)} CACAO playbooks")

        return PathResult(
            playbooks=playbooks,
            source="playbook_library_direct",
            confidence=1.0,
            technique_ids=enriched.technique_ids,
            technique_names=enriched.technique_names,
            tactics=enriched.tactics,
        )

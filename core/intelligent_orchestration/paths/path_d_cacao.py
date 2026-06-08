"""
Path D — LLM CACAO 2.0 Generation (Safety Net).

Input:  EnrichedAlert
Output: Optional[PathResult] — None only if LLM is completely unavailable

Stage 3 fallback when Paths A/B/C cannot produce high-confidence results.
Generates a structured OASIS CACAO 2.0 playbook via LLM with pre-assigned UUIDs
so cross-step references cannot break.

The result is always tagged LOW confidence; any generated playbook must be
reviewed by a human analyst before execution.
"""

import logging
from typing import Optional

from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.exceptions import LLMUnavailableError
from utils.llm.client import alert_to_text
from core.playbook_generation.cacao_generator import generate
from core.intelligent_orchestration.path_result import PathResult

logger = logging.getLogger(__name__)


class PathDRecommender:

    def run(self, enriched: EnrichedAlert) -> Optional[PathResult]:
        """
        Generate a CACAO 2.0 playbook for the alert.

        Returns None only when LLM is completely unavailable (no API key).
        The Orchestrator will surface an empty result in that case.
        """
        try:
            alert_text   = alert_to_text(enriched.raw)
            cacao        = generate(alert_text)
            playbook_ref = {
                "id":          cacao.get("id", "playbook--unknown"),
                "name":        cacao.get("name", "Generated Playbook"),
                "description": cacao.get("description", ""),
                "source":      "cacao_generated",
                "cacao":       cacao,
            }
            logger.info(
                f"[Path D] Generated CACAO playbook '{playbook_ref['name']}' "
                f"for {enriched.source_format} alert"
            )
            return PathResult(
                playbooks=[playbook_ref],
                source="cacao_generated",
                confidence=0.0,
                technique_ids=enriched.technique_ids,
                technique_names=enriched.technique_names,
                tactics=enriched.tactics,
                cacao_playbook=cacao,
            )
        except LLMUnavailableError:
            logger.warning("[Path D] LLM not configured — cannot generate playbook")
            return None
        except Exception as e:
            logger.error(f"[Path D] Generation failed: {e}", exc_info=True)
            return None

"""
Path B — LLM Technique Attribution.

Input:  EnrichedAlert (no MITRE tags, or tags present but Path A insufficient)
Output: Optional[PathResult] — None signals fall-through (LLM unavailable or
        LLM confidence below threshold)

The LLM identifies MITRE ATT&CK technique(s) from alert semantics, then
the PlaybookLibrary returns parameterized CACAO templates for those techniques.
Runs in parallel with Path C during Stage 2.
"""

import json
import logging
from typing import Dict, List, Optional

from core.config import config
from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.intelligent_orchestration.enrichment.ioc_extractor import IOCExtractor
from core.intelligent_orchestration.parameterizer import PlaybookParameterizer
from core.exceptions import LLMUnavailableError
from core.intelligent_orchestration.path_result import PathResult
from core.playbook_library.loader import PlaybookLibrary
from utils.llm.client import alert_to_text, call_llm, strip_fences

logger = logging.getLogger(__name__)


class PathBRecommender:

    def __init__(
        self,
        library:       PlaybookLibrary,
        ioc_extractor: IOCExtractor,
        parameterizer: PlaybookParameterizer,
    ) -> None:
        self._library       = library
        self._ioc_extractor = ioc_extractor
        self._parameterizer = parameterizer

    def run(self, enriched: EnrichedAlert, k: int) -> Optional[PathResult]:
        """
        Ask the LLM to attribute MITRE technique(s), then look up CACAO playbooks.

        Returns None when:
          - LLM API key not configured
          - LLM call raises an exception
          - LLM confidence < threshold
          - Library has no playbooks for the attributed techniques
        """
        try:
            text       = alert_to_text(enriched.raw)
            llm_result = self._attribute_technique(text)
        except LLMUnavailableError:
            logger.info("[Path B] LLM not configured")
            return None
        except Exception as exc:
            logger.warning(f"[Path B] LLM call failed: {exc}")
            return None

        if not llm_result:
            return None

        conf = float(llm_result.get("confidence", 0.0))
        if conf < config.llm.technique_confidence_threshold:
            logger.info(
                f"[Path B] LLM confidence {conf:.2f} < threshold "
                f"{config.llm.technique_confidence_threshold}"
            )
            return None

        attributed_ids   = llm_result.get("technique_ids", [])
        attributed_names = llm_result.get("technique_names", [])
        reasoning        = llm_result.get("reasoning", "")

        if not attributed_ids:
            return None

        iocs      = self._ioc_extractor.extract(enriched.raw)
        playbooks: List[Dict] = []
        seen: set = set()

        for tid in attributed_ids:
            for template in self._library.get_for_technique(tid):
                if template["id"] not in seen:
                    seen.add(template["id"])
                    pb = self._parameterizer.parameterize(template, iocs, enriched.raw)
                    playbooks.append(pb.to_dict())

        if not playbooks:
            logger.info(
                f"[Path B] LLM attributed {attributed_ids} but library has no templates"
            )
            return None

        playbooks = playbooks[:k]
        logger.info(
            f"[Path B] LLM → {attributed_ids} (conf={conf:.2f}) "
            f"→ {len(playbooks)} CACAO playbooks"
        )
        return PathResult(
            playbooks=playbooks,
            source="llm_attribution",
            confidence=conf,
            technique_ids=attributed_ids,
            technique_names=attributed_names,
            tactics=enriched.tactics,
            llm_reasoning=reasoning,
        )

    def _attribute_technique(self, alert_text: str) -> Optional[Dict]:
        prompt = (
            "You are a cybersecurity analyst. Analyze the security alert below and "
            "identify the most likely MITRE ATT&CK technique(s).\n\n"
            f"Alert:\n{alert_text}\n\n"
            "Respond with a JSON object ONLY (no markdown fences, no commentary):\n"
            '{"technique_ids": ["T1110.001"], "technique_names": ["Brute Force: Password Guessing"], '
            '"confidence": 0.92, "reasoning": "Multiple failed SSH logins from a single IP"}\n\n'
            "Rules:\n"
            "- Use only real MITRE ATT&CK IDs (TXXXX or TXXXX.XXX)\n"
            "- confidence is 0.0–1.0; be honest — below 0.5 means uncertain\n"
            "- Return at most 3 technique IDs, most likely first\n"
        )
        raw = call_llm(prompt, max_tokens=512)
        return json.loads(strip_fences(raw))

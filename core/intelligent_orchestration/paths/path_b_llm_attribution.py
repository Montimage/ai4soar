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

# When the LLM correctly attributes a technique but the library has no template for
# it, map to the closest available technique rather than dropping to Path D.
_TECHNIQUE_FALLBACK: Dict[str, str] = {
    # Network / endpoint DoS → DoS response playbook
    "T1498":     "T1499",
    "T1498.001": "T1499",
    "T1498.002": "T1499",
    # Exploitation techniques → public-facing application exploit response
    "T1203":     "T1190",
    "T1211":     "T1190",
    "T1212":     "T1190",
    # Active reconnaissance → block scanning source
    "T1595":     "T1110",
    "T1595.001": "T1110",
    "T1595.002": "T1110",
}


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
            # Try semantic fallbacks before giving up — handles cases where the LLM
            # correctly identifies a technique (e.g. T1498 DoS flood) that has no
            # dedicated playbook yet.
            fallback_ids: List[str] = []
            for tid in attributed_ids:
                target = _TECHNIQUE_FALLBACK.get(tid) or _TECHNIQUE_FALLBACK.get(tid.split(".")[0])
                if target and target not in fallback_ids:
                    fallback_ids.append(target)
            for ftid in fallback_ids:
                for template in self._library.get_for_technique(ftid):
                    if template["id"] not in seen:
                        seen.add(template["id"])
                        pb = self._parameterizer.parameterize(template, iocs, enriched.raw)
                        playbooks.append(pb.to_dict())
            if playbooks:
                logger.info(
                    f"[Path B] No templates for {attributed_ids}; "
                    f"fell back to {fallback_ids} → {len(playbooks)} playbook(s)"
                )
            else:
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

    # Loaded once at class level; safe because the file is read-only at runtime.
    _MITRE_NAMES: Dict[str, str] = {}

    @classmethod
    def _load_mitre_names(cls) -> None:
        if cls._MITRE_NAMES:
            return
        import json, os
        path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "mitre_techniques.json")
        path = os.path.normpath(path)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                cls._MITRE_NAMES = json.load(f)

    def _attribute_technique(self, alert_text: str) -> Optional[Dict]:
        self._library.load()  # ensure index is populated before reading _by_technique
        self._load_mitre_names()
        covered_ids = sorted({tid.split(".")[0] for tid in self._library._by_technique})
        covered_str = "\n".join(
            f"  {tid}: {self._MITRE_NAMES.get(tid, tid)}"
            for tid in covered_ids
        )
        prompt = (
            "You are a cybersecurity analyst. Analyze the security alert below and "
            "identify the most likely MITRE ATT&CK technique(s).\n\n"
            f"Alert:\n{alert_text}\n\n"
            "Supported techniques (you MUST pick only from this list):\n"
            f"{covered_str}\n\n"
            "Respond with a JSON object ONLY (no markdown fences, no commentary):\n"
            '{"technique_ids": ["T1110.001"], "technique_names": ["Brute Force: Password Guessing"], '
            '"confidence": 0.92, "reasoning": "Multiple failed SSH logins from a single IP"}\n\n'
            "Rules:\n"
            "- Select the technique ID(s) from the supported list above that best match the alert\n"
            "- Sub-techniques (TXXXX.XXX) are allowed if the parent is in the list\n"
            "- confidence is 0.0–1.0; be honest — below 0.5 means uncertain\n"
            "- Return at most 3 technique IDs, most likely first\n"
        )
        raw = call_llm(prompt, max_tokens=512)
        return json.loads(strip_fences(raw))

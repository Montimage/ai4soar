"""
Path B — LLM Technique Attribution.

Input:  EnrichedAlert (no MITRE tags, or tags present but Path A insufficient)
Output: Optional[PathResult] — None signals fall-through (LLM unavailable or
        LLM confidence below threshold)

The LLM identifies MITRE ATT&CK technique(s) from alert semantics, then
the PlaybookLibrary returns parameterized CACAO templates for those techniques.
Runs in parallel with Path C during Stage 2.

Prompt, vocabulary and response parsing come from utils/llm/attribution.py — the same
module the offline evaluator (scripts/evaluate_llm_attribution.py) drives, so the
accuracy measured on the 37-alert benchmark describes this code path. Two consequences
worth knowing:

  * The candidate list is the FULL ATT&CK v19.1 Enterprise matrix (697 techniques), not
    just the techniques the playbook library covers. The model attributes honestly and
    we then map its ranking onto whatever templates exist; a correct attribution with no
    template is a library gap, and is logged as one rather than being hidden by forcing
    the model to pick a covered technique.
  * That makes the prompt ~9.3K tokens. Local models MUST be given a context window
    large enough for it (config.llm.num_ctx) or Ollama silently discards the front of
    the prompt — the vocabulary — and accuracy collapses to near zero.
"""

import logging
from typing import Dict, List, Optional, Tuple

from core.config import config
from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.intelligent_orchestration.enrichment.ioc_extractor import IOCExtractor
from core.intelligent_orchestration.parameterizer import PlaybookParameterizer
from core.exceptions import LLMUnavailableError
from core.intelligent_orchestration.path_result import PathResult
from core.playbook_library.loader import PlaybookLibrary
from utils.llm.attribution import (
    build_prompt,
    in_vocab,
    load_vocab,
    parse_prediction,
    technique_name,
    vocab_string,
)
from utils.llm.client import alert_to_text, attribution_spec, call_model, output_budget

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

# Confidence assigned when the model returns a well-formed ranking
_DERIVED_CONFIDENCE = {
    "clean_full":    0.75,   # valid JSON, top-1 in vocab, full ranking returned
    "clean_partial": 0.60,   # valid JSON, top-1 in vocab, short ranking
    "regex":         0.50,   # ids recovered by regex from prose
    "salvaged":      0.40,   # answer channel empty, ids taken from thinking channel
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
        self._ctx_warned    = False

    def run(self, enriched: EnrichedAlert, k: int) -> Optional[PathResult]:
        """
        Ask the LLM to attribute MITRE technique(s), then look up CACAO playbooks.

        Returns None when:
          - LLM API key not configured
          - LLM call raises an exception
          - the response yields no in-vocabulary technique ID
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

        ranked   = llm_result["ranked"]
        conf     = llm_result["confidence"]
        reasoning = llm_result["reasoning"]

        if not ranked:
            return None

        if conf < config.llm.technique_confidence_threshold:
            logger.info(
                f"[Path B] LLM confidence {conf:.2f} < threshold "
                f"{config.llm.technique_confidence_threshold} (ranked={ranked})"
            )
            return None

        iocs = self._ioc_extractor.extract(enriched.raw)
        selected, playbooks = self._playbooks_for(ranked, iocs, enriched.raw, k)

        if not playbooks:
            logger.info(
                f"[Path B] LLM attributed {ranked} but library has no templates "
                f"(coverage gap)"
            )
            return None

        logger.info(
            f"[Path B] LLM → {ranked} (conf={conf:.2f}), acted on {selected} "
            f"→ {len(playbooks)} CACAO playbooks"
        )
        return PathResult(
            playbooks=playbooks,
            source="llm_attribution",
            confidence=conf,
            technique_ids=selected,
            technique_names=[technique_name(t) for t in selected],
            ranked_technique_ids=ranked,
            tactics=self._tactics_for(ranked[0], enriched.tactics),
            llm_reasoning=reasoning,
        )

    # -----------------------------------------------------------------------
    # Technique → playbooks
    # -----------------------------------------------------------------------
    def _playbooks_for(
        self, ranked: List[str], iocs: Dict, raw: Dict, k: int
    ) -> Tuple[List[str], List[Dict]]:
        """Walk the ranking in order, collecting templates until k playbooks are found.

        Returns (technique ids that actually contributed, parameterized playbooks).
        """
        seen: set = set()
        selected: List[str] = []
        playbooks: List[Dict] = []

        for tid in ranked:
            if len(playbooks) >= k:
                break
            hit = False
            for template in self._library.get_for_technique(tid):
                if template["id"] not in seen:
                    seen.add(template["id"])
                    playbooks.append(
                        self._parameterizer.parameterize(template, iocs, raw).to_dict()
                    )
                    hit = True
            if hit:
                selected.append(tid)

        if playbooks:
            return selected, playbooks[:k]

        fallback_pairs: List[Tuple[str, str]] = []
        for tid in ranked:
            target = _TECHNIQUE_FALLBACK.get(tid) or _TECHNIQUE_FALLBACK.get(tid.split(".")[0])
            if target and target not in {t for _, t in fallback_pairs}:
                fallback_pairs.append((tid, target))

        for tid, target in fallback_pairs:
            if len(playbooks) >= k:
                break
            for template in self._library.get_for_technique(target):
                if template["id"] not in seen:
                    seen.add(template["id"])
                    playbooks.append(
                        self._parameterizer.parameterize(template, iocs, raw).to_dict()
                    )
                    if tid not in selected:
                        selected.append(tid)

        if playbooks:
            logger.info(
                f"[Path B] No templates for {ranked}; fell back to "
                f"{[t for _, t in fallback_pairs]} → {len(playbooks)} playbook(s)"
            )
        return selected, playbooks[:k]

    def _tactics_for(self, top_technique: str, enriched_tactics: List[str]) -> List[str]:
        """Tactics for the top-1 attribution, unioned with any the alert already carried.

        Path B runs precisely when the alert has NO MITRE tags, so enriched.tactics is
        usually empty — without deriving tactics from the attribution, the decision
        engine's tactic-agreement check between Path B and a tactic-predicting Path C
        model can never fire.
        """
        _, tactics_by_id, _ = load_vocab("all")
        derived = tactics_by_id.get(top_technique) or tactics_by_id.get(
            top_technique.split(".")[0]
        ) or []
        merged = list(enriched_tactics)
        for t in derived:
            if t not in merged:
                merged.append(t)
        return merged

    # -----------------------------------------------------------------------
    # LLM call
    # -----------------------------------------------------------------------
    def _attribute_technique(self, alert_text: str) -> Optional[Dict]:
        """Return {ranked, confidence, reasoning} or None if nothing usable came back."""
        vocab  = vocab_string(config.llm.attribution_vocab)
        prompt = build_prompt(vocab, alert_text, ask_confidence=True)
        spec   = attribution_spec()
        self._warn_if_context_too_small(prompt, spec)

        resp = call_model(spec, prompt)
        pred = parse_prediction(resp.text, resp.reasoning)

        if resp.finish == "length":
            logger.warning(
                f"[Path B] {spec['model']} hit its output cap "
                f"({output_budget(spec)} tokens) — raise LLM_ATTRIBUTION_MAX_TOKENS "
                f"(thinking models need ~16384, plus LLM_NUM_CTX=32768)"
            )
        if pred["from_reasoning"]:
            logger.warning(
                f"[Path B] {spec['model']} returned an empty answer channel; ranking "
                f"recovered from its reasoning text — treat this attribution as weak"
            )

        valid   = in_vocab(pred["ranked"])
        dropped = [t for t in pred["ranked"] if t not in set(valid)]
        ranked  = valid[: config.llm.attribution_ranked_k]
        if dropped:
            # The model recalled ATT&CK ids from its weights instead of selecting from
            # the candidate list; those ids cannot be looked up and must not be reported.
            logger.warning(
                f"[Path B] {spec['model']} returned {len(dropped)} id(s) outside "
                f"ATT&CK v19.1: {dropped}"
            )
        if not ranked:
            logger.info(f"[Path B] no in-vocabulary technique in response: {resp.text[:200]!r}")
            return None

        conf = pred["confidence"]
        if conf is None:
            conf = self._derive_confidence(pred)
            logger.info(
                f"[Path B] {spec['model']} omitted \"confidence\"; derived {conf:.2f} "
                f"from parse quality"
            )

        return {"ranked": ranked, "confidence": conf, "reasoning": pred["reasoning"]}

    @staticmethod
    def _derive_confidence(pred: Dict) -> float:
        if pred["from_reasoning"]:
            return _DERIVED_CONFIDENCE["salvaged"]
        if not pred["json_valid"]:
            return _DERIVED_CONFIDENCE["regex"]
        if len(pred["ranked"]) >= config.llm.attribution_ranked_k:
            return _DERIVED_CONFIDENCE["clean_full"]
        return _DERIVED_CONFIDENCE["clean_partial"]

    def _warn_if_context_too_small(self, prompt: str, spec: Dict) -> None:
        """Ollama drops the FRONT of an over-long prompt (the vocabulary) without error.

        Same guard the evaluator prints at startup; logged once per recommender.
        """
        if spec["provider"] != "ollama" or self._ctx_warned:
            return
        approx_tok = int(len(prompt) / 2.5)
        budget = approx_tok + spec.get("max_tokens", 0)
        if budget > spec["num_ctx"]:
            self._ctx_warned = True
            logger.warning(
                f"[Path B] prompt+output (~{approx_tok}+{spec.get('max_tokens')}) exceeds "
                f"num_ctx={spec['num_ctx']} for {spec['model']} — Ollama will silently "
                f"drop the front of the prompt (the candidate vocabulary) and accuracy "
                f"will collapse. Raise LLM_NUM_CTX or set "
                f"LLM_ATTRIBUTION_VOCAB=parents."
            )

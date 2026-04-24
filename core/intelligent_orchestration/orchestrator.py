"""
PlaybookOrchestrator — 3-stage recommendation engine.

Stage 1 (instant)
  Run Path A (direct library lookup for known techniques).
  If technique IDs are known AND confidence ≥ early_exit_threshold → HIGH, done.

Stage 2 (parallel)
  Run Path B (LLM technique attribution) and Path C (ML similarity) concurrently.
  Fuse their results via the Decision Engine.
  If fused confidence ≥ low_confidence_threshold → MEDIUM or HIGH, done.

Stage 3 (fallback)
  Run Path D (LLM CACAO 2.0 generation).
  Always LOW confidence — mandatory human review.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from core.config import config
from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.intelligent_orchestration.enrichment.ioc_extractor import IOCExtractor
from core.intelligent_orchestration.parameterizer import PlaybookParameterizer
from core.intelligent_orchestration.decision_engine.confidence import classify
from core.intelligent_orchestration.decision_engine.fusion import fuse
from core.intelligent_orchestration.orchestration_result import OrchestrationResult
from core.intelligent_orchestration.path_result import PathResult
from core.intelligent_orchestration.paths.path_a_stix import PathARecommender
from core.intelligent_orchestration.paths.path_b_llm_attribution import PathBRecommender
from core.intelligent_orchestration.paths.path_c_ml_similarity import PathCRecommender
from core.intelligent_orchestration.paths.path_d_cacao import PathDRecommender
from core.playbook_library.loader import PlaybookLibrary

logger = logging.getLogger(__name__)


class PlaybookOrchestrator:
    """
    Stateful orchestrator — instantiate once and reuse across requests.
    Paths B, C, and D are I/O-bound so ThreadPoolExecutor is appropriate.
    """

    def __init__(self) -> None:
        library       = PlaybookLibrary(config.playbook_library.path)
        ioc_extractor = IOCExtractor()
        parameterizer = PlaybookParameterizer()

        self._path_a = PathARecommender(library, ioc_extractor, parameterizer)
        self._path_b = PathBRecommender(library, ioc_extractor, parameterizer)
        self._path_c = PathCRecommender(library, ioc_extractor, parameterizer)
        self._path_d = PathDRecommender()

    def orchestrate(self, enriched: EnrichedAlert, k: int = 5) -> OrchestrationResult:
        """
        Run the 3-stage pipeline and return a fully classified OrchestrationResult.

        Args:
            enriched: Alert after enrichment (technique IDs, tactics, etc.)
            k:        Maximum number of playbooks to return.
        """
        # ── Stage 1: Path A ──────────────────────────────────────────────
        if enriched.technique_ids:
            a = self._path_a.run(enriched, k)
            if a.playbooks and a.confidence >= config.orchestration.early_exit_threshold:
                tier = classify(a.confidence)
                logger.info(
                    f"[Orchestrator] Stage 1 exit: Path A → tier={tier} "
                    f"conf={a.confidence:.2f} playbooks={len(a.playbooks)}"
                )
                return self._build_result(a, tier, paths=["A"])

        # ── Stage 2: Path B + C in parallel ──────────────────────────────
        b_result: Optional[PathResult] = None
        c_result: Optional[PathResult] = None

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(self._path_b.run, enriched, k): "B",
                pool.submit(self._path_c.run, enriched, k): "C",
            }
            for future in as_completed(futures):
                tag = futures[future]
                try:
                    result = future.result()
                    if tag == "B":
                        b_result = result
                    else:
                        c_result = result
                except Exception as exc:
                    logger.error(f"[Orchestrator] Path {tag} raised: {exc}", exc_info=True)

        fused = fuse(b_result, c_result)

        if fused.playbooks and fused.confidence >= config.orchestration.low_confidence_threshold:
            tier = classify(fused.confidence)
            logger.info(
                f"[Orchestrator] Stage 2 exit: paths={fused.paths_used} "
                f"source={fused.source} tier={tier} conf={fused.confidence:.2f}"
            )
            return OrchestrationResult(
                playbooks=fused.playbooks[:k],
                source=fused.source,
                confidence=fused.confidence,
                confidence_tier=tier,
                paths_used=fused.paths_used,
                technique_ids=fused.technique_ids,
                technique_names=fused.technique_names,
                tactics=fused.tactics,
                llm_reasoning=fused.llm_reasoning,
            )

        # ── Stage 3: Path D ───────────────────────────────────────────────
        logger.info("[Orchestrator] Stage 3: invoking Path D (CACAO generation)")
        d = self._path_d.run(enriched)

        if d and d.playbooks:
            return self._build_result(d, "LOW", paths=["D"])

        logger.warning("[Orchestrator] All paths failed — returning empty result")
        return OrchestrationResult(
            playbooks=[],
            source="none",
            confidence=0.0,
            confidence_tier="LOW",
            paths_used=[],
            technique_ids=enriched.technique_ids,
            technique_names=enriched.technique_names,
            tactics=enriched.tactics,
        )

    @staticmethod
    def _build_result(pr: PathResult, tier: str, paths: list) -> OrchestrationResult:
        return OrchestrationResult(
            playbooks=pr.playbooks,
            source=pr.source,
            confidence=pr.confidence,
            confidence_tier=tier,
            paths_used=paths,
            technique_ids=pr.technique_ids,
            technique_names=pr.technique_names,
            tactics=pr.tactics,
            llm_reasoning=pr.llm_reasoning,
            cacao_playbook=pr.cacao_playbook,
        )

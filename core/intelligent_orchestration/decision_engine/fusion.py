"""
Stage 2 fusion — combine Path B (LLM technique attribution) and
Path C (ML similarity) into a single FusedResult.

Fusion rules
────────────
B wins (technique-level precision):
  Use Path B's playbooks.
  If Path C is also available AND agrees on technique/tactic → confirmation bonus.
  Agreement check:
    - If Path C predicted a T-code  → check technique_ids overlap with B
    - If Path C predicted a tactic  → check tactic matches one of B's tactics

C only:
  Use Path C's playbooks.
  - T-code model: no confidence discount (matches Path A/B precision)
  - Tactic model: apply PATH_C_DISCOUNT (broader, less targeted)

Neither available:
  Return a zero-confidence FusedResult so the Orchestrator falls through
  to Path D.

The discount and bonus factors live in OrchestrationConfig so they can be
tuned without touching this file.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_TCODE_RE = re.compile(r"^T\d{4}")

from core.config import config
from core.intelligent_orchestration.path_result import PathResult

logger = logging.getLogger(__name__)


@dataclass
class FusedResult:
    """Output of the fusion step, consumed by the Orchestrator."""
    playbooks: List[Dict]
    source: str                     # fused | llm_attribution | ml_classifier | no_data
    confidence: float
    paths_used: List[str]           # subset of ["B", "C"]
    technique_ids: List[str]        = field(default_factory=list)
    technique_names: List[str]      = field(default_factory=list)
    tactics: List[str]              = field(default_factory=list)
    predicted_tactic: str           = ""
    llm_reasoning: str              = ""


def fuse(
    b: Optional[PathResult],
    c: Optional[PathResult],
) -> FusedResult:
    """
    Merge Path B and Path C results.

    Args:
        b: PathResult from Path B (may be None if LLM unavailable or low-confidence).
        c: PathResult from Path C (may be None if ML model not trained).

    Returns:
        FusedResult with combined confidence and playbooks.
    """
    b_ok = b is not None and bool(b.playbooks)
    c_ok = c is not None and bool(c.playbooks)

    if not b_ok and not c_ok:
        logger.info("[Fusion] Both B and C returned no playbooks → no_data")
        return FusedResult(
            playbooks=[], source="no_data", confidence=0.0, paths_used=[]
        )

    if b_ok:
        return _fuse_b_primary(b, c if c_ok else None)

    return _fuse_c_only(c)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _c_is_tcode(c: PathResult) -> bool:
    """True if Path C predicted a T-code (not a tactic phase)."""
    return bool(c.technique_ids) or bool(
        c.predicted_tactic and _TCODE_RE.match(c.predicted_tactic)
    )


def _fuse_b_primary(b: PathResult, c: Optional[PathResult]) -> FusedResult:
    """Path B is the primary signal; Path C may boost confidence."""
    conf   = b.confidence
    source = "llm_attribution"
    paths  = ["B"]

    if c is not None:
        paths.append("C")
        agreed = False
        if _c_is_tcode(c):
            # T-code model: check technique overlap
            if set(b.technique_ids) & set(c.technique_ids):
                agreed = True
                agree_on = f"technique(s) {set(b.technique_ids) & set(c.technique_ids)}"
        else:
            # Tactic model: check tactic overlap
            if c.predicted_tactic and c.predicted_tactic in set(b.tactics):
                agreed = True
                agree_on = f"tactic '{c.predicted_tactic}'"

        if agreed:
            bonus  = config.orchestration.confirmation_bonus
            conf   = min(conf + bonus, 1.0)
            source = "fused"
            logger.info(
                f"[Fusion] B+C agree on {agree_on} "
                f"→ confidence boosted by {bonus:.2f} to {conf:.2f}"
            )
        else:
            logger.info(
                f"[Fusion] B techniques={b.technique_ids} tactics={b.tactics} "
                f"vs C technique_ids={c.technique_ids} tactic={c.predicted_tactic} "
                "— no agreement, no bonus"
            )

    return FusedResult(
        playbooks=b.playbooks,
        source=source,
        confidence=conf,
        paths_used=paths,
        technique_ids=b.technique_ids,
        technique_names=b.technique_names,
        tactics=b.tactics,
        llm_reasoning=b.llm_reasoning,
    )


def _fuse_c_only(c: PathResult) -> FusedResult:
    """
    Only Path C fired — apply a discount regardless of target type.

    T-code model: real-world P@1 ~0.34 on unseen scenarios (scenario-level eval).
      Reported test metrics (0.63) are inflated by alert-level data leakage in the
      training corpus.  A discount of PATH_C_DISCOUNT (default 0.85) keeps Path C
      in MEDIUM range when confident but prevents it from triggering early-exit alone.

    Tactic model: same discount, coarser signal.
    """
    discount = config.orchestration.path_c_discount
    logger.info(
        f"[Fusion] Only Path C ({'T-code' if _c_is_tcode(c) else 'tactic'} model) → "
        f"conf={c.confidence:.2f} × {discount} = {c.confidence * discount:.2f}"
    )
    conf = c.confidence * discount
    return FusedResult(
        playbooks=c.playbooks,
        source="ml_classifier",
        confidence=conf,
        paths_used=["C"],
        technique_ids=c.technique_ids,
        tactics=[c.predicted_tactic] if c.predicted_tactic else c.tactics,
        predicted_tactic=c.predicted_tactic,
    )

"""
OrchestrationResult — the final output of PlaybookOrchestrator.orchestrate().

Wraps the winning PathResult / FusedResult with routing metadata so the API
layer and downstream consumers know how to handle the recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class OrchestrationResult:
    """
    Fields
    ------
    playbooks       : ranked list of recommendation dicts
    source          : which path(s) produced the result
    confidence      : 0.0–1.0 composite score
    confidence_tier : HIGH | MEDIUM | LOW
    paths_used      : e.g. ["A"], ["B", "C"], ["D"]
    technique_ids   : attributed ATT&CK technique IDs (may be empty)
    technique_names : human-readable technique names
    tactics         : attributed ATT&CK tactics
    llm_reasoning   : free-text explanation from LLM (Path B only)
    cacao_playbook  : full CACAO 2.0 dict when Path D was used (else None)
    """

    playbooks:        List[Dict[str, Any]]
    source:           str
    confidence:       float
    confidence_tier:  str                       # HIGH | MEDIUM | LOW
    paths_used:       List[str]
    technique_ids:    List[str]  = field(default_factory=list)
    technique_names:  List[str]  = field(default_factory=list)
    tactics:          List[str]  = field(default_factory=list)
    llm_reasoning:    str        = ""
    cacao_playbook:   Optional[Dict] = None

    # ------------------------------------------------------------------
    # Routing helpers consumed by the API layer
    # ------------------------------------------------------------------

    @property
    def auto_executable(self) -> bool:
        """HIGH confidence → safe to hand off to orchestration engine."""
        return self.confidence_tier == "HIGH"

    @property
    def requires_human_approval(self) -> bool:
        """MEDIUM confidence → analyst should approve before execution."""
        return self.confidence_tier == "MEDIUM"

    @property
    def requires_human_review(self) -> bool:
        """LOW confidence → mandatory review; never auto-execute."""
        return self.confidence_tier == "LOW"

    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbooks":              self.playbooks,
            "source":                 self.source,
            "confidence":             round(self.confidence, 4),
            "confidence_tier":        self.confidence_tier,
            "paths_used":             self.paths_used,
            "technique_ids":          self.technique_ids,
            "technique_names":        self.technique_names,
            "tactics":                self.tactics,
            "llm_reasoning":          self.llm_reasoning,
            "auto_executable":        self.auto_executable,
            "requires_human_approval": self.requires_human_approval,
            "requires_human_review":  self.requires_human_review,
            "cacao_playbook":         self.cacao_playbook,
        }

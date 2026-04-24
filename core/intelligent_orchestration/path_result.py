"""
PathResult — raw output from a single recommendation path (A / B / C / D).

Paths return PathResult. The Decision Engine fuses multiple PathResults
into an OrchestrationResult with a confidence tier attached.
Keeping these two types separate means paths stay focused on their own
logic and the Decision Engine owns the fusion and routing policy.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PathResult:
    """Raw result returned by one recommendation path."""

    playbooks: List[Dict]           # [{id, name, description}, ...]
    source: str                     # stix_direct | llm_attribution |
                                    # similarity_model | cacao_generated | no_data
    confidence: float               # 1.0 (A) | LLM prob (B) | model prob (C) | 0.0 (D)

    technique_ids: List[str]        = field(default_factory=list)
    technique_names: List[str]      = field(default_factory=list)
    tactics: List[str]              = field(default_factory=list)
    predicted_tactic: str           = ""
    llm_reasoning: str              = ""
    cacao_playbook: Optional[Dict]  = None

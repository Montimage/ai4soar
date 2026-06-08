"""
PlaybookVerifier — structural + LLM-based verification for SOAR playbooks.

Supports three input formats:
  - CACAO 2.0 JSON  (from our intelligent orchestration pipeline)
  - Shuffle JSON    (manually created workflows in Shuffle SOAR)
  - Internal nodes  ({nodes: [{id, name, description, next}]})

Verification layers:
  1. Spec compliance  — CACAO-specific: UUID, required fields, no stray {{placeholders}}
  2. Structural       — graph analysis: DAG check, start/end nodes, dead steps
  3. LLM semantic     — logical contradiction detection (optional, requires API key)
"""

import logging
import os
import re
import uuid as _uuid_mod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

logger = logging.getLogger(__name__)

_UUID_RE      = re.compile(r"^playbook--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PLACEHOLDER  = re.compile(r"\{\{\w+\}\}")


class VerificationScore(Enum):
    NO_ERROR       = 100
    MINOR_ISSUE    = 80
    MODERATE_ISSUE = 60
    MAJOR_ISSUE    = 40
    CRITICAL_ISSUE = 20


@dataclass
class VerificationIssue:
    description: str
    score:       int
    node_id:     Optional[str] = None
    severity:    str           = "warning"


@dataclass
class NodeInfo:
    id:          str
    name:        str
    description: str
    api:         Optional[str]  = None
    next_nodes:  List[str]      = None


# ------------------------------------------------------------------
# Format adapters
# ------------------------------------------------------------------

def cacao_to_verifier_nodes(cacao: Dict) -> Dict:
    """
    Convert a CACAO 2.0 playbook dict → internal verifier node format.

    Edges are built from on_success / on_failure / on_completion links.
    """
    workflow = cacao.get("workflow", {})
    nodes: List[Dict] = []

    for step_id, step in workflow.items():
        nexts = []
        for key in ("on_success", "on_failure", "on_completion"):
            target = step.get(key)
            if target and target != step_id:
                nexts.append(target)

        cmds = step.get("commands", [])
        description = " | ".join(c.get("command", "")[:80] for c in cmds) if cmds else ""

        nodes.append({
            "id":          step_id,
            "name":        step.get("name", step_id),
            "description": description,
            "next":        nexts,
        })

    return {"nodes": nodes}


def shuffle_to_verifier_nodes(shuffle_json: Dict) -> Dict:
    """Convert a Shuffle workflow JSON → internal verifier node format."""
    nodes: Dict[str, Dict] = {}

    for action in shuffle_json.get("actions", []):
        node_id = action["id"]
        code_param = next(
            (p["value"] for p in action.get("parameters", []) if p["name"] == "code"),
            None,
        )
        nodes[node_id] = {
            "id":          node_id,
            "name":        action.get("label") or action.get("name", ""),
            "description": action.get("description", ""),
            "api":         action.get("app_name", ""),
            "parameters":  {p["name"]: p.get("value", "") for p in action.get("parameters", [])},
            "code":        code_param,
            "next":        [],
        }

    for branch in shuffle_json.get("branches", []):
        src, dst = branch["source_id"], branch["destination_id"]
        if src in nodes:
            nodes[src]["next"].append(dst)

    return {"nodes": list(nodes.values())}


# Keep old name for backward compatibility
simplify_shuffle_playbook = shuffle_to_verifier_nodes


# ------------------------------------------------------------------
# CACAO spec checks (format-specific, runs before graph analysis)
# ------------------------------------------------------------------

def verify_cacao_spec(cacao: Dict, is_template: bool = False) -> List[VerificationIssue]:
    """
    Check CACAO 2.0 required fields and formatting rules.
    Returns a list of spec violations (empty = compliant).

    is_template=True skips the {{placeholder}} check — templates intentionally
    leave variables un-substituted until execution time.
    """
    issues: List[VerificationIssue] = []

    # Required top-level fields (created/modified are instance-specific; skip for templates)
    instance_fields = () if is_template else ("created", "modified")
    for field in ("type", "spec_version", "id", "name", "workflow_start", "workflow") + instance_fields:
        if field not in cacao:
            issues.append(VerificationIssue(
                description=f"Missing required CACAO 2.0 field: '{field}'",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error",
            ))

    # type must be "playbook"
    if cacao.get("type") != "playbook":
        issues.append(VerificationIssue(
            description=f"'type' must be 'playbook', got '{cacao.get('type')}'",
            score=VerificationScore.MAJOR_ISSUE.value,
            severity="error",
        ))

    # spec_version must be "cacao-2.0"
    if cacao.get("spec_version") != "cacao-2.0":
        issues.append(VerificationIssue(
            description=f"'spec_version' must be 'cacao-2.0', got '{cacao.get('spec_version')}'",
            score=VerificationScore.MAJOR_ISSUE.value,
            severity="error",
        ))

    # id must be playbook--<UUID4>
    pb_id = cacao.get("id", "")
    if not _UUID_RE.match(pb_id):
        issues.append(VerificationIssue(
            description=f"'id' must be 'playbook--<UUID4>', got '{pb_id}'",
            score=VerificationScore.MAJOR_ISSUE.value,
            severity="error",
        ))

    # workflow_start must reference an existing step
    workflow = cacao.get("workflow", {})
    ws = cacao.get("workflow_start")
    if ws and ws not in workflow:
        issues.append(VerificationIssue(
            description=f"'workflow_start' references unknown step '{ws}'",
            score=VerificationScore.CRITICAL_ISSUE.value,
            severity="error",
        ))

    # on_success / on_failure / on_completion must reference existing steps
    for step_id, step in workflow.items():
        for key in ("on_success", "on_failure", "on_completion"):
            target = step.get(key)
            if target and target not in workflow:
                issues.append(VerificationIssue(
                    description=f"Step '{step_id}'.{key} references unknown step '{target}'",
                    score=VerificationScore.CRITICAL_ISSUE.value,
                    node_id=step_id,
                    severity="error",
                ))

    # No unresolved {{placeholders}} in instantiated playbooks (skip for templates)
    if not is_template:
        for ph in sorted(set(_find_placeholders(cacao))):
            issues.append(VerificationIssue(
                description=f"Unresolved placeholder '{ph}' — IOC missing from alert",
                score=VerificationScore.MODERATE_ISSUE.value,
                severity="warning",
            ))

    return issues


def _find_placeholders(obj: Any) -> List[str]:
    found: List[str] = []
    if isinstance(obj, str):
        found.extend(_PLACEHOLDER.findall(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            found.extend(_find_placeholders(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_find_placeholders(item))
    return found


# ------------------------------------------------------------------
# Main verifier class
# ------------------------------------------------------------------

class PlaybookVerifier:

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def verify(
        self,
        data: Dict,
        structural_only: bool = False,
        is_template: bool = False,
    ) -> Dict:
        """
        Auto-detect format and verify.

        Accepts:
          - CACAO 2.0 dict (has 'spec_version': 'cacao-2.0' or 'workflow' key)
          - Shuffle JSON  (has 'actions' key)
          - Internal nodes format (has 'nodes' key)

        is_template=True skips {{placeholder}} warnings (used for library templates).
        """
        spec_issues: List[VerificationIssue] = []

        if "spec_version" in data or "workflow" in data:
            spec_issues = verify_cacao_spec(data, is_template=is_template)
            node_data   = cacao_to_verifier_nodes(data)
        elif "actions" in data:
            node_data = shuffle_to_verifier_nodes(data)
        else:
            node_data = data

        return self._run(node_data, spec_issues=spec_issues, structural_only=structural_only)

    def verify_playbook(self, playbook_data: Dict, structural_only: bool = False) -> Dict:
        """Legacy entry point — accepts internal node format."""
        return self._run(playbook_data, spec_issues=[], structural_only=structural_only)

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _run(
        self,
        node_data:       Dict,
        spec_issues:     List[VerificationIssue],
        structural_only: bool,
    ) -> Dict:
        G, nodes_info       = self._parse(node_data)
        structural_issues   = self._verify_structure(G)
        llm_issues: List[VerificationIssue] = []

        llm_status = "skipped"
        if not structural_only:
            try:
                llm_issues = self._verify_with_llm(nodes_info)
                llm_status = "no_contradictions" if not llm_issues else "contradictions_found"
            except Exception as exc:
                logger.warning(f"[Verifier] LLM check skipped: {exc}")
                llm_status = f"error: {exc}"

        all_issues = spec_issues + structural_issues + llm_issues
        overall    = min((i.score for i in all_issues), default=VerificationScore.NO_ERROR.value)

        return {
            "overall_score": overall,
            "passed":        overall >= VerificationScore.MODERATE_ISSUE.value,
            "llm_checked":   llm_status,
            "issues": [
                {
                    "description": i.description,
                    "score":       i.score,
                    "node_id":     i.node_id,
                    "severity":    i.severity,
                }
                for i in all_issues
            ],
        }

    def _parse(self, playbook_data: Dict) -> Tuple[nx.DiGraph, Dict[str, NodeInfo]]:
        G           = nx.DiGraph()
        nodes_info  = {}
        for node in playbook_data.get("nodes", []):
            node_id  = node.get("id")
            info     = NodeInfo(
                id=node_id,
                name=node.get("name", ""),
                description=node.get("description", ""),
                api=node.get("api"),
                next_nodes=node.get("next", []),
            )
            nodes_info[node_id] = info
            G.add_node(node_id)
        for node_id, info in nodes_info.items():
            for nxt in (info.next_nodes or []):
                G.add_edge(node_id, nxt)
        return G, nodes_info

    def _verify_structure(self, G: nx.DiGraph) -> List[VerificationIssue]:
        issues: List[VerificationIssue] = []

        if not nx.is_directed_acyclic_graph(G):
            issues.append(VerificationIssue(
                description="Workflow contains cycles — may loop indefinitely",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error",
            ))

        start_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        if not start_nodes:
            issues.append(VerificationIssue(
                description="No start node found (no node with in-degree 0)",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error",
            ))

        end_nodes = [n for n in G.nodes() if G.out_degree(n) == 0]
        if not end_nodes:
            issues.append(VerificationIssue(
                description="No end node found (no node with out-degree 0)",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error",
            ))

        # Unreachable steps (not reachable from any start node)
        if start_nodes:
            reachable = set()
            for s in start_nodes:
                reachable |= nx.descendants(G, s) | {s}
            unreachable = set(G.nodes()) - reachable
            for n in unreachable:
                issues.append(VerificationIssue(
                    description=f"Step '{n}' is unreachable from the workflow start",
                    score=VerificationScore.MINOR_ISSUE.value,
                    node_id=n,
                    severity="warning",
                ))

        return issues

    def _verify_with_llm(self, nodes_info: Dict[str, NodeInfo]) -> List[VerificationIssue]:
        context = (
            "You are a playbook verification expert focused on identifying logical contradictions. "
            "Analyze the following playbook steps to detect sequences of actions that are impossible "
            "or illogical (e.g., analyzing a file after it has been deleted). "
            "Focus ONLY on logical contradictions. Do NOT report minor issues or best practices. "
            "If no contradiction is found, state: 'No logical contradiction detected.'\n\n"
        )
        for node_id, node in nodes_info.items():
            context += f"Step {node_id} — {node.name}\n"
            if node.description:
                context += f"  Action: {node.description}\n"
            if node.api:
                context += f"  API: {node.api}\n"
            if node.next_nodes:
                context += f"  Next: {', '.join(node.next_nodes)}\n"
            context += "\n"

        from utils.llm.client import call_llm
        analysis = call_llm(context, max_tokens=512)

        issues: List[VerificationIssue] = []
        if "no logical contradiction detected" not in analysis.strip().lower():
            issues.append(VerificationIssue(
                description=analysis,
                score=VerificationScore.MODERATE_ISSUE.value,
                severity="warning",
            ))
        return issues

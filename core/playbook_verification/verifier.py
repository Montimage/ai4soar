"""
PlaybookVerifier — structural + LLM-based verification for SOAR playbooks.

Supports three input formats:
  - CACAO 2.0 JSON  (from our intelligent orchestration pipeline)
  - Shuffle JSON    (manually created workflows in Shuffle SOAR)
  - Internal nodes  ({nodes: [{id, name, description, next}]})

Verification is a fixed list of named criteria in four groups (CRITERIA below), each
reported as pass / warning / error / info / skipped, so the UI can show what was checked
and not only what failed:
  1. CACAO 2.0 compliance — required fields, official OASIS schema, values filled
  2. Workflow structure   — links, entry and exit, loops, reachability
  3. Commands             — bash syntax (bash -n), response-action safety policy
  4. LLM review           — commands real, matching the step, no harmful side effects,
                            sensible order (optional, one LLM call)
"""

import json
import logging
import os
import re
import subprocess
import uuid as _uuid_mod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.config import config

import networkx as nx

logger = logging.getLogger(__name__)

# CACAO 2.0 workflow step types (data/cacao-schemas/workflows/). 'single' belongs
# to the pre-2.0 drafts and is NOT valid here.
_CACAO_STEP_TYPES = frozenset({
    "start", "end", "action", "playbook-action",
    "parallel", "if-condition", "while-condition", "switch-condition",
})

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
    category:    str           = ""        # spec | schema | safety | syntax | structural | llm
    check:       str           = ""        # criterion id, see CRITERIA
    line:        str           = ""        # the offending command line, when known


# (group id, group label, [(criterion id, label, what it checks)]). The UI renders this
# list, so a new check is added here and reported with check=<its id>.
CRITERIA = [
    ("cacao", "CACAO 2.0 compliance", [
        ("cacao.fields", "Required fields and step types",
         "type, spec_version, id, start and end steps, CACAO 2.0 step types"),
        ("cacao.schema", "Official CACAO 2.0 schema", "validates against the OASIS JSON schema"),
        ("cacao.filled", "Values filled from the alert", "no {{placeholder}} left empty"),
    ]),
    ("structure", "Workflow structure", [
        ("structure.links", "Links point to existing steps", "every next step exists"),
        ("structure.start_end", "One entry and an exit", "the flow has a first and a last step"),
        ("structure.loops", "No loops", "the flow cannot cycle forever"),
        ("structure.reachable", "Every step reachable", "no step is cut off from the start"),
    ]),
    ("commands", "Commands", [
        ("commands.syntax", "Bash syntax", "each bash command parses (bash -n): quotes, brackets, if/fi"),
        ("commands.safety", "Safety policy",
         "no recursive delete, disk wipe, shutdown, firewall flush, unscoped DROP, "
         "kill by pattern (pkill -f), chmod 777, log destruction, curl | sh"),
    ]),
    ("llm", "LLM review", [
        ("llm.valid", "Commands are real", "each line is a valid Linux command with sensible arguments"),
        ("llm.purpose", "Commands match the step", "they do what the step name and description say"),
        ("llm.side_effects", "No harmful side effects", "nothing destructive beyond the step's purpose"),
        ("llm.order", "Steps in a sensible order", "no step relies on what an earlier step removed"),
    ]),
]


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

def verify_cacao_spec(cacao: Dict, is_template: bool = False,
                      optional_params: Sequence[str] = (),
                      secret_params: Sequence[str] = ()) -> List[VerificationIssue]:
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
                description=f"Missing required CACAO 2.0 field: '{field}'", check="cacao.fields",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error",
            ))

    # type must be "playbook"
    if cacao.get("type") != "playbook":
        issues.append(VerificationIssue(
            description=f"'type' must be 'playbook', got '{cacao.get('type')}'", check="cacao.fields",
            score=VerificationScore.MAJOR_ISSUE.value,
            severity="error",
        ))

    # spec_version must be "cacao-2.0"
    if cacao.get("spec_version") != "cacao-2.0":
        issues.append(VerificationIssue(
            description=f"'spec_version' must be 'cacao-2.0', got '{cacao.get('spec_version')}'", check="cacao.fields",
            score=VerificationScore.MAJOR_ISSUE.value,
            severity="error",
        ))

    # id must be playbook--<UUID4>
    pb_id = cacao.get("id", "")
    if not _UUID_RE.match(pb_id):
        issues.append(VerificationIssue(
            description=f"'id' must be 'playbook--<UUID4>', got '{pb_id}'", check="cacao.fields",
            score=VerificationScore.MAJOR_ISSUE.value,
            severity="error",
        ))

    # workflow_start must reference an existing step
    workflow = cacao.get("workflow", {})
    ws = cacao.get("workflow_start")
    if ws and ws not in workflow:
        issues.append(VerificationIssue(
            description=f"'workflow_start' references unknown step '{ws}'", check="structure.links",
            score=VerificationScore.CRITICAL_ISSUE.value,
            severity="error",
        ))

    # CACAO 2.0 mandates a start step, an action/playbook-action step and an end step,
    # and workflow_start MUST point at the start step (data/cacao-schemas/playbook.json).
    # The structural pass below finds entry points by in-degree, which cannot tell a
    # conformant start step from an action that simply happens to be first.
    if ws and ws in workflow:
        ws_type = (workflow[ws] or {}).get("type")
        if ws_type != "start":
            issues.append(VerificationIssue(
                description=(
                    f"'workflow_start' must reference a step of type 'start', "
                    f"but '{ws}' is type '{ws_type}'"
                ),
                score=VerificationScore.MAJOR_ISSUE.value,
                node_id=ws,
                severity="error", check="cacao.fields",
            ))

    step_types = [(step or {}).get("type") for step in workflow.values()]
    for required, label in (("start", "start"), ("end", "end")):
        if required not in step_types:
            issues.append(VerificationIssue(
                description=f"Workflow has no '{label}' step; CACAO 2.0 requires one", check="cacao.fields",
                score=VerificationScore.MAJOR_ISSUE.value,
                severity="error",
            ))

    # Step types outside the CACAO 2.0 vocabulary (e.g. the pre-2.0 'single')
    for step_id, step in workflow.items():
        st = (step or {}).get("type")
        if st and st not in _CACAO_STEP_TYPES:
            issues.append(VerificationIssue(
                description=(
                    f"Step '{step_id}' has type '{st}', which is not a CACAO 2.0 "
                    f"workflow step type"
                ), check="cacao.fields",
                score=VerificationScore.MAJOR_ISSUE.value,
                node_id=step_id,
                severity="error",
            ))

    # on_success / on_failure / on_completion must reference existing steps
    for step_id, step in workflow.items():
        for key in ("on_success", "on_failure", "on_completion"):
            target = step.get(key)
            if target and target not in workflow:
                issues.append(VerificationIssue(
                    description=f"Step '{step_id}'.{key} references unknown step '{target}'",
                    check="structure.links",
                    score=VerificationScore.CRITICAL_ISSUE.value,
                    node_id=step_id,
                    severity="error",
                ))

    # No unresolved {{placeholders}} in instantiated playbooks (skip for templates)
    # A placeholder of a parameter the template declares OPTIONAL is expected to stay
    # empty when the alert has no such field: reported as info, without a penalty.
    if not is_template:
        optional = set(optional_params)
        for ph in sorted(set(_find_placeholders(cacao))):
            if ph.strip("{}") in secret_params:
                continue     # an API key, filled from .env in the deployed workflow only
            if ph.strip("{}") in optional:
                issues.append(VerificationIssue(
                    description=f"Optional value '{ph}' not filled: the steps using it have nothing to act on",
                    check="cacao.filled",
                    score=VerificationScore.NO_ERROR.value,
                    severity="info",
                ))
            else:
                issues.append(VerificationIssue(
                    description=f"Unresolved placeholder '{ph}' — not filled: the alert lacks this field, or its .env setting is unset",
                    check="cacao.filled",
                    score=VerificationScore.MODERATE_ISSUE.value,
                    severity="warning",
                ))

    return issues


def _tag(issues: List[VerificationIssue], category: str) -> List[VerificationIssue]:
    for i in issues:
        i.category = i.category or category
    return issues


def _schema_issues(cacao: Dict) -> Optional[List[VerificationIssue]]:
    """Official OASIS CACAO 2.0 schema errors; None when the validator is unavailable."""
    from core.playbook_verification.schema import schema_errors
    errors = schema_errors(cacao)
    if errors is None:
        return None
    issues = []
    for e in errors:
        node = e["path"].split("/")[1] if e["path"].startswith("workflow/") else None
        if e.get("unfilled"):
            # Same cause as the "Unresolved placeholder" spec issue, already reported
            continue
        else:
            issues.append(VerificationIssue(
                description=f"Official CACAO schema: {e['path']}: {e['message'][:200]}",
                score=VerificationScore.MAJOR_ISSUE.value, node_id=node,
                severity="error", category="schema", check="cacao.schema"))
    return issues


def _safety_issues(cacao: Dict) -> List[VerificationIssue]:
    """Commands matching the response-action safety policy (policy.py), as warnings."""
    from core.playbook_verification.policy import describe, policy_violations
    issues = []
    for step_id, step in (cacao.get("workflow") or {}).items():
        for cmd in (step or {}).get("commands") or []:
            for rule in policy_violations(str(cmd.get("command", ""))):
                issues.append(VerificationIssue(
                    description=f"Safety policy '{rule}' in step '{step.get('name') or step_id}': {describe(rule)}",
                    score=VerificationScore.MINOR_ISSUE.value,
                    node_id=step_id,
                    severity="warning",
                    category="safety", check="commands.safety",
                    line=_matching_line(str(cmd.get("command", "")), rule)))
    return issues


def _matching_line(text: str, rule: str) -> str:
    from core.playbook_verification.policy import policy_violations
    return next((ln.strip() for ln in text.splitlines() if rule in policy_violations(ln)), "")


def _command_text(cmd: Dict) -> str:
    if cmd.get("command") is not None:
        return str(cmd["command"])
    if cmd.get("command_b64"):
        import base64
        try:
            return base64.b64decode(cmd["command_b64"]).decode("utf-8", "replace")
        except Exception:
            return ""
    return ""


def _syntax_issues(cacao: Dict) -> Optional[List[VerificationIssue]]:
    """bash -n on every bash command: catches unbalanced quotes, brackets, if/fi... (not
    unknown programs: bash only finds those when it runs). None if bash is missing."""
    issues = []
    for step_id, step in (cacao.get("workflow") or {}).items():
        for cmd in (step or {}).get("commands") or []:
            if (cmd.get("type") or "bash") != "bash":
                continue
            text = _command_text(cmd)
            try:
                r = subprocess.run(["bash", "-n"], input=text, capture_output=True, text=True, timeout=5)
            except FileNotFoundError:
                return None
            except subprocess.TimeoutExpired:
                continue
            if r.returncode:
                msg = (r.stderr.strip().splitlines() or ["syntax error"])[0]
                msg = re.sub(r"^bash: (line \d+: )?", "", msg)
                m = re.search(r"line (\d+)", r.stderr)
                lines = text.splitlines()
                line = lines[int(m.group(1)) - 1].strip() if m and 0 < int(m.group(1)) <= len(lines) else ""
                issues.append(VerificationIssue(
                    description=f"Step '{step.get('name') or step_id}': bash syntax error: {msg}",
                    score=VerificationScore.MAJOR_ISSUE.value, node_id=step_id,
                    severity="error", category="syntax", check="commands.syntax", line=line))
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
        optional_params: Sequence[str] = (),
        secret_params: Sequence[str] = (),
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
        checks: Dict = {}
        # criterion id -> why it was not run (shown as "skipped")
        skipped: Dict[str, str] = {}
        llm_steps: Optional[List[Dict]] = None

        if "spec_version" in data or "workflow" in data:
            spec_issues = _tag(verify_cacao_spec(data, is_template=is_template,
                                                 optional_params=optional_params,
                                                 secret_params=secret_params), "spec")
            checks["spec"] = sum(1 for i in spec_issues if i.severity != "info")
            # Templates keep readable step keys and {{placeholders}}: the official schema
            # applies to the parameterized playbook, not to the template
            if is_template:
                skipped["cacao.schema"] = "templates are checked once filled for an alert"
                skipped["cacao.filled"] = "templates keep their {{placeholders}}"
            else:
                schema = _schema_issues(data)
                checks["schema"] = "unavailable" if schema is None else len(schema)
                if schema is None:
                    skipped["cacao.schema"] = "schema validator unavailable"
                spec_issues += schema or []
            syntax = _syntax_issues(data)
            if syntax is None:
                skipped["commands.syntax"] = "bash is not installed"
            spec_issues += syntax or []
            safety = _safety_issues(data)
            checks["safety"] = len(safety)
            spec_issues += safety
            node_data = cacao_to_verifier_nodes(data)
            llm_steps = _cacao_llm_steps(data)
        elif "actions" in data:
            node_data = shuffle_to_verifier_nodes(data)
        else:
            node_data = data
        if llm_steps is None:
            for cid in ("cacao.fields", "cacao.schema", "cacao.filled",
                        "commands.syntax", "commands.safety"):
                skipped[cid] = "CACAO playbooks only"

        result = self._run(node_data, spec_issues=spec_issues, structural_only=structural_only,
                           llm_steps=llm_steps, skipped=skipped)
        result["checks"] = {**checks, **result["checks"]}
        return result

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
        llm_steps:       Optional[List[Dict]] = None,
        skipped:         Optional[Dict[str, str]] = None,
    ) -> Dict:
        skipped = dict(skipped or {})
        G, nodes_info       = self._parse(node_data)
        structural_issues   = _tag(self._verify_structure(G), "structural")
        llm_issues: List[VerificationIssue] = []

        llm_status = "skipped"
        if structural_only:
            for cid, *_ in CRITERIA[-1][2]:
                skipped[cid] = "LLM review not requested"
        else:
            try:
                steps = llm_steps if llm_steps is not None else _node_llm_steps(nodes_info)
                llm_issues = _tag(self._verify_with_llm(steps), "llm")
                llm_status = "no_contradictions" if not llm_issues else "contradictions_found"
            except Exception as exc:
                logger.warning(f"[Verifier] LLM check skipped: {exc}")
                llm_status = f"error: {exc}"
                for cid, *_ in CRITERIA[-1][2]:
                    skipped[cid] = f"LLM review failed: {exc}"

        all_issues = spec_issues + structural_issues + llm_issues
        overall    = min((i.score for i in all_issues), default=VerificationScore.NO_ERROR.value)
        criteria, summary = _criteria_report(all_issues, skipped)
        errors = any(i.severity == "error" for i in all_issues)
        warnings = any(i.severity == "warning" for i in all_issues)

        return {
            # "failed": at least one error; "warnings": to review before running;
            # "passed": nothing to report. overall_score (worst single issue) is kept for
            # the metrics scripts; the UI shows the verdict and the criteria.
            "verdict":       "failed" if errors else "warnings" if warnings else "passed",
            "summary":       summary,
            "criteria":      criteria,
            "overall_score": overall,
            "passed":        not errors,
            "llm_checked":   llm_status,
            "issues": [
                {
                    "description": i.description,
                    "score":       i.score,
                    "node_id":     i.node_id,
                    "severity":    i.severity,
                    "category":    i.category,
                    "check":       i.check,
                    "line":        i.line,
                }
                for i in all_issues
            ],
            "checks": {"structural": len(structural_issues), "llm": llm_status},
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
                severity="error", check="structure.loops",
            ))

        start_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        if not start_nodes:
            issues.append(VerificationIssue(
                description="No start node found (no node with in-degree 0)",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error", check="structure.start_end",
            ))

        end_nodes = [n for n in G.nodes() if G.out_degree(n) == 0]
        if not end_nodes:
            issues.append(VerificationIssue(
                description="No end node found (no node with out-degree 0)",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error", check="structure.start_end",
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
                    severity="warning", check="structure.reachable",
                ))

        return issues

    def _verify_with_llm(self, steps: List[Dict]) -> List[VerificationIssue]:
        """One LLM call reviewing every step against the four llm.* criteria."""
        from utils.llm.client import strip_fences
        labels = {st["id"]: f"S{n}" for n, st in enumerate(steps, 1)}
        names = {st["id"]: st["name"] for st in steps}
        text = ""
        for st in steps:
            text += f"{labels[st['id']]} \"{st['name']}\" ({st['type']})\n"
            if st.get("description"):
                text += f"  Purpose: {st['description']}\n"
            if st.get("target"):
                text += f"  Runs on: {st['target']}\n"
            for c in st.get("commands") or []:
                text += f"  Command ({c['type']}):\n" + "".join(
                    f"    {ln}\n" for ln in (c["text"] or "(empty)").splitlines())
            nxt = [labels.get(n, n) for n in st.get("next") or []]
            if nxt:
                text += f"  Next: {', '.join(nxt)}\n"
            text += "\n"

        prompt = (
            "You review a security response playbook before a SOC operator runs it on a real "
            "host. Check every step against these criteria:\n"
            "  valid        - each command line is a real, correctly written Linux command "
            "(existing program, valid options and arguments). Random words, typos and "
            "truncated commands fail.\n"
            "  purpose      - the commands do what the step's name and purpose say.\n"
            "  side_effects - nothing destructive or broader than the step needs (deleting "
            "data, killing unrelated processes, cutting off the whole host when one address "
            "should be blocked).\n"
            "  order        - the sequence is logical: no step relies on something an earlier "
            "step removed or changed.\n"
            "{{name}} placeholders are values filled in later from the alert: treat them as "
            "valid. Report real problems only, not style or best-practice suggestions.\n"
            "Answer with JSON only, no prose:\n"
            '{"issues": [{"step": "S2", "check": "valid|purpose|side_effects|order", '
            '"severity": "error|warning", "line": "<the offending command line, or empty>", '
            '"message": "<one short sentence>"}]}\n'
            'Use "error" when the step cannot work or would do harm, "warning" otherwise. '
            'Answer {"issues": []} when everything is fine.\n\n'
            f"Playbook steps:\n{text}"
        )
        from utils.llm.client import call_model, resolve_spec
        resp = call_model(resolve_spec(max_tokens=config.llm.verify_max_tokens,
                                       temperature=0.1, seed=None), prompt)
        if resp.finish == "refusal" and not resp.text:
            # The model's safety filter declined the commands themselves (log wiping,
            # remote code...): a finding in its own right, not a failed check
            return [VerificationIssue(
                description="The LLM declined to review these commands because they look "
                            "harmful: check every step by hand before running it",
                score=VerificationScore.MAJOR_ISSUE.value, severity="error",
                check="llm.side_effects")]
        raw = strip_fences(resp.text or resp.reasoning)
        m = re.search(r"\{.*\}", raw, re.S)
        try:
            found = json.loads(m.group(0) if m else raw).get("issues") or []
        except (ValueError, AttributeError):
            raise ValueError(f"unreadable LLM answer: {raw[:200]}")

        by_label = {v: k for k, v in labels.items()}
        issues: List[VerificationIssue] = []
        for f in found:
            check = str(f.get("check", "")).strip()
            if check not in ("valid", "purpose", "side_effects", "order"):
                check = "order"
            node = by_label.get(str(f.get("step", "")).strip())
            sev = "error" if f.get("severity") == "error" else "warning"
            where = f"Step '{names[node]}': " if node else ""
            issues.append(VerificationIssue(
                description=f"{where}{str(f.get('message', '')).strip()}",
                score=(VerificationScore.MAJOR_ISSUE if sev == "error"
                       else VerificationScore.MINOR_ISSUE).value,
                node_id=node, severity=sev, check=f"llm.{check}",
                line=str(f.get("line") or "").strip()))
        return issues


def _cacao_llm_steps(cacao: Dict) -> List[Dict]:
    """The steps as the LLM review sees them: full commands, purpose, target, next."""
    wf = cacao.get("workflow") or {}
    targets = cacao.get("target_definitions") or {}
    steps = []
    for sid, st in wf.items():
        st = st or {}
        if st.get("type") in ("start", "end"):
            continue
        nxt = [st[k] for k in ("on_completion", "on_success", "on_failure", "on_true", "on_false")
               if st.get(k)] + list(st.get("next_steps") or []) + list((st.get("cases") or {}).values())
        steps.append({
            "id": sid, "name": st.get("name") or sid, "type": st.get("type", "action"),
            "description": st.get("description", ""),
            "target": ", ".join((targets.get(t) or {}).get("name", t) for t in st.get("targets") or []),
            "commands": [{"type": c.get("type") or "bash",
                          "text": _command_text(c) + (f"\n{c['content']}" if c.get("content") else "")}
                         for c in st.get("commands") or []],
            "next": [n for n in dict.fromkeys(nxt) if n in wf and (wf[n] or {}).get("type") != "end"],
        })
    return steps


def _node_llm_steps(nodes_info: Dict[str, NodeInfo]) -> List[Dict]:
    return [{"id": nid, "name": n.name or nid, "type": "step", "description": "",
             "commands": [{"type": "action", "text": n.description or n.api or ""}],
             "next": list(n.next_nodes or [])}
            for nid, n in nodes_info.items()]


def _criteria_report(issues: List[VerificationIssue], skipped: Dict[str, str]) -> Tuple[List[Dict], Dict]:
    """CRITERIA with a status each: error > warning > info > pass, or skipped."""
    rank = {"error": 3, "warning": 2, "info": 1}
    groups, counts = [], {"pass": 0, "info": 0, "warning": 0, "error": 0, "skipped": 0}
    for gid, glabel, items in CRITERIA:
        out = []
        for cid, label, what in items:
            mine = [i for i in issues if i.check == cid]
            if cid in skipped and not mine:
                status = "skipped"
            elif mine:
                status = max((i.severity for i in mine), key=lambda s: rank.get(s, 0))
            else:
                status = "pass"
            counts[status] = counts.get(status, 0) + 1
            out.append({"id": cid, "label": label, "checks": what, "status": status,
                        "note": skipped.get(cid, "") if status == "skipped" else ""})
        groups.append({"id": gid, "label": glabel, "criteria": out})
    run = sum(v for k, v in counts.items() if k != "skipped")
    return groups, {**counts, "run": run, "ok": counts["pass"] + counts["info"]}

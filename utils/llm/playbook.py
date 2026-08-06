"""
Shared CACAO playbook-generation primitives — prompt, scaffold, response parsing.

Path D asks an LLM to turn a security alert directly into an executable CACAO 2.0
playbook. Nothing from playbooks/ is shown to the model: no library template, no
example playbook, no technique hint. The playbook must come from the model's own
knowledge plus the alert text, which is what makes the measurement about the model
rather than about our library.

This module is the single definition of that prompt and of how the answer is read back,
so the offline evaluator (scripts/evaluate_path_d.py) and production Path D can import
the same thing — the arrangement already used for attribution (utils/llm/attribution.py).

Three generation modes, in increasing order of scaffolding. The mode is the independent
variable of the Path D experiment: more scaffolding trades the model's freedom to choose
a workflow shape against our guarantee that the output is spec-compliant.

  free      — "produce a CACAO 2.0 playbook", nothing else. Tests whether the model
              knows the standard unaided.
  schema    — required fields, id format and linking rules, but NOT the step graph.
              The model still decides which steps exist and how they connect.
  skeleton  — a fixed 5-step scaffold with UUIDs pre-assigned; the model fills in
              names, descriptions and commands only.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

MODES = ("free", "schema", "skeleton")

REQUIRED_FIELDS = ("type", "spec_version", "id", "name", "created_by",
                   "created", "modified", "workflow_start", "workflow")
STEP_TYPES = ("start", "end", "action", "playbook-action", "parallel",
              "if-condition", "while-condition", "switch-condition")
COMMAND_TYPES = ("bash", "http-api", "ssh", "caldera-cmd", "elastic", "jupyter",
                 "kestrel", "openc2-http", "powershell", "sigma", "yara", "manual")
AI4SOAR_IDENTITY = "identity--b7f0d5a2-9c31-4e88-8a61-7d2f4c9e0a15"


# ---------------------------------------------------------------------------
# Scaffold
# ---------------------------------------------------------------------------
_NS = uuid.UUID("6f1f0b6e-1c3a-4d5e-9a7b-2c8d3e4f5a60")   # arbitrary, fixed namespace
_EPOCH = "2026-01-01T00:00:00Z"


def build_skeleton(seed: Optional[str] = None) -> Dict:
    """A fixed investigate → contain → recover → document → end scaffold."""
    if seed is None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        mk  = lambda _role: uuid.uuid4()
    else:
        now = _EPOCH
        mk  = lambda role: uuid.uuid5(_NS, f"{seed}|{role}")

    s_invest  = f"action--{mk('investigate')}"
    s_contain = f"action--{mk('contain')}"
    s_recover = f"action--{mk('recover')}"
    s_report  = f"action--{mk('document')}"
    s_end     = f"end--{mk('end')}"
    agent     = f"individual--{mk('agent')}"
    return {
        "type":           "playbook",
        "spec_version":   "cacao-2.0",
        "id":             f"playbook--{mk('playbook')}",
        "name":           "<fill: descriptive playbook name>",
        "description":    "<fill: what this playbook does>",
        "playbook_types": ["notification", "investigation", "remediation"],
        "external_references": [{
            "source":      "mitre-attack",
            "external_id": "<fill: the MITRE ATT&CK technique id for this alert>",
            "name":        "<fill: that technique's name>",
        }],
        "created_by":     AI4SOAR_IDENTITY,
        "created":        now,
        "modified":       now,
        "agent_definitions": {agent: {"type": "individual", "name": "SOC analyst"}},
        "workflow_start": s_invest,
        "workflow": {
            s_invest: {
                "type": "action", "name": "Investigate", "agent": agent,
                "description": "<fill: what evidence to gather>",
                "commands": [{"type": "bash", "command": "<fill: investigation command>"}],
                "on_completion": s_contain,
            },
            s_contain: {
                "type": "action", "name": "Contain", "agent": agent,
                "description": "<fill: how to isolate or block the threat>",
                "commands": [{"type": "bash", "command": "<fill: containment command>"}],
                "on_completion": s_recover,
            },
            s_recover: {
                "type": "action", "name": "Recover", "agent": agent,
                "description": "<fill: how to restore normal operations>",
                "commands": [{"type": "bash", "command": "<fill: recovery command>"}],
                "on_completion": s_report,
            },
            s_report: {
                "type": "action", "name": "Document", "agent": agent,
                "description": "<fill: what to record about this incident>",
                "commands": [{"type": "bash", "command": "<fill: documentation command>"}],
                "on_completion": s_end,
            },
            s_end: {"type": "end"},
        },
    }


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------
_TASK = """You are a senior SOC incident-response engineer.

Given the security alert below, produce an executable CACAO 2.0 response playbook \
that an analyst could run to investigate, contain and recover from THIS specific \
incident.

Alert:
"""

_SPEC_RULES = """
CACAO 2.0 requirements (OASIS Security Playbooks v2.0):
- Required top-level properties: "type" (always "playbook"), "spec_version" (always
  "cacao-2.0"), "id", "name", "created_by", "created", "modified", "workflow_start",
  "workflow". Add "description" and "playbook_types" as well.
- Every identifier has the form "<object-type>--<UUID>", where <object-type> is the exact
  "type" value of the object being identified and <UUID> is a REAL random RFC 4122
  version-4 UUID: lowercase hex in 8-4-4-4-12 groups whose 13th hex digit is "4" and whose
  17th is one of 8, 9, a or b. Decorative or sequential hex is NOT a UUID and is rejected.
  Generate a fresh UUID for each identifier, and never reuse one that appears in this
  prompt.
- "id" is "playbook--<UUIDv4>"; "created_by" is an identity reference,
  "identity--<UUIDv4>".
- "created" and "modified" are UTC timestamps, e.g. "2026-01-31T12:00:00Z".
- "workflow" is an object keyed by step id, and a step id MUST use that step's own "type"
  as its prefix: an "action" step is keyed "action--<UUIDv4>", a "start" step
  "start--<UUIDv4>", an "end" step "end--<UUIDv4>", and likewise for "if-condition",
  "while-condition", "parallel", "playbook-action" and "switch-condition". "step--" is a
  CACAO 1.1 form and is NOT valid in 2.0.
- "workflow_start" MUST be the id of a step that exists in "workflow".
- Each step's "type" MUST be one of: "start", "end", "action", "playbook-action",
  "parallel", "if-condition", "while-condition", "switch-condition". Use "action" for a
  step that runs commands — "single" is CACAO 1.1 and is NOT valid in 2.0.
- Every "action" step has "name", "description", a non-empty "commands" array of
  {"type": "bash", "command": "<the command>"} objects, AND "agent" — the identifier of
  the executor that runs those commands.
- Each non-"action" step type carries its own required properties, so use a type only if
  you supply them: "if-condition" and "while-condition" need "condition" plus "on_true"
  (and may add "on_false"); "parallel" needs "next_steps", an array of step ids;
  "switch-condition" needs "switch" plus "cases"; "playbook-action" needs "playbook_id".
  "start" and "end" steps need nothing beyond their linking property.
- Declare every agent referenced by an "agent" property in a top-level
  "agent_definitions" object, keyed by that same identifier: a key of the form
  "individual--<UUIDv4>" whose value is {"type": "individual", "name": "<the executor>"}.
- Steps link forward with "on_completion" (or "on_success"/"on_failure"), whose value
  MUST be the id of another step in "workflow".
- There MUST be at least one step with "type": "end", reachable from "workflow_start".
"""

_ATTACK_RULE = """
- Record the MITRE ATT&CK technique this playbook responds to as a single
  "external_references" entry of the form
  {"source": "mitre-attack", "external_id": "<the technique id you determined>",
   "name": "<that technique's name>"}
  Give the single most likely technique for THIS alert. This is a declaration of what you
  are responding to, not a request to enumerate options.
"""

_CONTENT_RULES = """
Content requirements:
- Every command must be a real, runnable shell command — no pseudo-code, no
  placeholders, no "<...>" or "{{...}}" left in the output.
- Use the actual indicators from the alert above (IP addresses, domains, URLs,
  usernames, ports, process names) directly in the commands. Do not invent indicators
  that do not appear in the alert.
- Prefer commands that are safe to run on a production host, and put any destructive
  or disruptive action in its own step with a description saying what it affects.
"""

_ONLY_JSON = "\nOutput the JSON object and nothing else — no markdown fences, no commentary."


def build_prompt(alert_text: str, mode: str = "schema",
                 technique: Optional[str] = None,
                 seed: Optional[str] = None) -> str:
    """Render the Path D prompt for one alert."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")

    parts = [_TASK, alert_text.rstrip(), "\n"]
    if technique:
        parts.append(f"\nThe alert has been attributed to MITRE ATT&CK technique "
                     f"{technique}. Respond to that technique.\n")

    if mode == "free":
        parts.append("\nRespond with a single CACAO 2.0 playbook as a JSON object.")
        parts.append(_CONTENT_RULES)
        parts.append(_ATTACK_RULE)
    elif mode == "schema":
        parts.append("\nRespond with a single CACAO 2.0 playbook as a JSON object.")
        parts.append(_SPEC_RULES)
        parts.append(_CONTENT_RULES)
        parts.append(_ATTACK_RULE)
    else:  # skeleton
        parts.append("\nFill in the skeleton below. Replace every <fill: ...> placeholder "
                     "with specific, actionable content. Keep ALL step ids, timestamps "
                     "and top-level fields exactly as given — do not add or remove "
                     "steps.\n\n")
        parts.append(json.dumps(build_skeleton(seed), indent=2))
        parts.append("\n")
        parts.append(_CONTENT_RULES)

    parts.append(_ONLY_JSON)
    return "".join(parts)


_THINK = re.compile(r"<(think|thinking|reasoning)>.*?(</\1>|\Z)", re.S)


def strip_think(s: str) -> str:
    return _THINK.sub("", s).strip()


def _first_json_object(s: str) -> Optional[Dict]:
    """Extract the first balanced {...} block and parse it.

    Needed because models append trailing prose after a valid object; json.loads on the
    whole string fails and the playbook would be scored as unparseable.
    """
    start = s.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(s[start:], start):
        if in_str:
            if esc:      esc = False
            elif ch == "\\": esc = True
            elif ch == '"':  in_str = False
            continue
        if ch == '"':   in_str = True
        elif ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(s[start:i + 1])
                except Exception:
                    return None
                return obj if isinstance(obj, dict) else None
    return None


def parse_playbook(raw: str, reasoning: str = "") -> Dict:
    """Return {playbook, json_valid, parse_ok, from_reasoning}.

    `json_valid` means the whole answer was one clean JSON object; a playbook recovered
    from surrounding prose sets parse_ok without json_valid, so the two can be reported
    apart. `reasoning` is the thinking channel, used only when the answer channel is
    empty (thinking model truncated before its final message).
    """
    out = {"playbook": None, "json_valid": False, "parse_ok": False,
           "from_reasoning": False}
    body = strip_think(raw or "")
    s = body.strip()
    if s.startswith("```"):
        chunks = s.split("```")
        if len(chunks) > 1:
            s = chunks[1]
            if s.startswith("json"):
                s = s[4:]
        s = s.strip()

    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            out["playbook"], out["json_valid"] = obj, True
    except Exception:
        obj = _first_json_object(body)
        if obj is not None:
            out["playbook"] = obj

    if out["playbook"] is not None:
        out["parse_ok"] = bool(out["playbook"].get("workflow"))

    if not out["parse_ok"] and (reasoning or "").strip():
        alt = parse_playbook(reasoning)
        if alt["parse_ok"]:
            alt["json_valid"] = False
            alt["from_reasoning"] = True
            return alt
    return out


# ---------------------------------------------------------------------------
# Command extraction (used by the scorer and the judge)
# ---------------------------------------------------------------------------
def iter_commands(playbook: Dict) -> List[Tuple[str, str]]:
    """[(step_id, command string)] for every command in the workflow, order preserved."""
    out: List[Tuple[str, str]] = []
    for step_id, step in (playbook.get("workflow") or {}).items():
        if not isinstance(step, dict):
            continue
        for cmd in (step.get("commands") or []):
            if isinstance(cmd, dict):
                c = cmd.get("command")
            else:
                c = cmd
            if isinstance(c, str) and c.strip():
                out.append((step_id, c))
    return out


def iter_commands_typed(playbook: Dict) -> List[Tuple[str, str, str]]:
    """[(step_id, command type, command string)] — the type is needed because `bash -n`
    is meaningless for an http-api or openc2-http command."""
    out: List[Tuple[str, str, str]] = []
    for step_id, step in (playbook.get("workflow") or {}).items():
        if not isinstance(step, dict):
            continue
        for cmd in (step.get("commands") or []):
            if isinstance(cmd, dict):
                c, t = cmd.get("command"), str(cmd.get("type") or "")
            else:
                c, t = cmd, "bash"
            if isinstance(c, str) and c.strip():
                out.append((step_id, t, c))
    return out


def all_text(obj) -> str:
    """Every string anywhere in the playbook, newline-joined — for grounding checks."""
    acc: List[str] = []

    def walk(o):
        if isinstance(o, str):
            acc.append(o)
        elif isinstance(o, dict):
            for k, v in o.items():
                acc.append(str(k)); walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
        elif o is not None:
            acc.append(str(o))

    walk(obj)
    return "\n".join(acc)

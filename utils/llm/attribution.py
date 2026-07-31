"""
Shared MITRE ATT&CK attribution primitives — vocabulary, prompt, response parsing.

This module is the single definition of the attribution prompt and of how a model's
answer is read back. Both the production recommender
(core/intelligent_orchestration/paths/path_b_llm_attribution.py) and the offline
evaluator (scripts/evaluate_llm_attribution.py) import from here, so the prompt that
was benchmarked is the prompt that runs in production.

IMPORTANT — prompt stability: the evaluator's response cache is keyed on a hash of the
rendered prompt, so editing PROMPT_TEMPLATE invalidates every cached run. The
`ask_confidence` flag exists precisely so production can request one extra JSON key
without changing the bytes of the benchmarked (ask_confidence=False) prompt.

Vocabulary files (ATT&CK v19.1):
  data/attack_enterprise_all.json      697 techniques {id: {name, tactics}}
  data/attack_enterprise_parents.json  222 parent techniques {id: name}
"""

import functools
import json
import os
import re
from typing import Dict, List, Optional, Tuple

ROOT      = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VOCAB_ALL = os.path.join(ROOT, "data", "attack_enterprise_all.json")
VOCAB_PAR = os.path.join(ROOT, "data", "attack_enterprise_parents.json")

# Number of ranked candidates the model is asked for. The prompt hard-codes five
# "Txxxx" placeholders, so changing this alone is not enough — keep them in sync.
TOP_K = 5


# ---------------------------------------------------------------------------
# Prompt
#
# The template renders to the exact string used for the 37-alert benchmark when
# extra_rules="" (see build_prompt / ask_confidence). {vocab} and {alert} are the
# per-call fills; {shape} and {extra_rules} are set by ask_confidence.
# ---------------------------------------------------------------------------
PROMPT_TEMPLATE = """You are a SOC analyst performing MITRE ATT&CK technique attribution.

Given the security alert below, identify the FIVE most likely MITRE ATT&CK \
Enterprise techniques, ranked from most likely (rank 1) to least likely (rank 5).

You MUST choose every technique_id from this list (id: name), and from nowhere else:
{vocab}

Alert:
{alert}

Respond with a JSON object ONLY (no markdown, no commentary), in this exact SHAPE
(the IDs below are placeholders showing the format — do NOT copy them):
{shape}

Rules:
- Provide EXACTLY 5 technique IDs, ranked most likely first, with no duplicates.
- The "Txxxx" above are a FORMAT EXAMPLE ONLY — do not reuse them. Choose the real
  IDs from the list above based on what THIS alert actually shows.
- Every ID MUST be one of the IDs in the list above.
- If you are confident of a specific sub-technique (e.g. use the "id: name" line for
  it), use it; otherwise use the parent technique ID.{extra_rules}
- Output the JSON and nothing else."""

# Substituted into {shape} as a literal value, so single braces (str.format does not
# re-scan replacement text).
_SHAPE = ('{"techniques": ["Txxxx", "Txxxx", "Txxxx", "Txxxx", "Txxxx"], '
          '"reasoning": "one short sentence"}')
_SHAPE_CONF = ('{"techniques": ["Txxxx", "Txxxx", "Txxxx", "Txxxx", "Txxxx"], '
               '"confidence": 0.92, "reasoning": "one short sentence"}')

# Appended only when ask_confidence=True; the leading newline continues the rule list.
_CONF_RULE = ('\n- "confidence" is how certain you are of the rank-1 ID, from 0.0 to 1.0.'
              '\n  Be honest: below 0.5 means you are guessing.')


def build_prompt(vocab: str, alert: str, ask_confidence: bool = False) -> str:
    """Render the attribution prompt.

    ask_confidence=False reproduces the benchmarked prompt byte-for-byte.
    ask_confidence=True adds a "confidence" key to the requested JSON shape, which
    production gates on (config.llm.technique_confidence_threshold).
    """
    return PROMPT_TEMPLATE.format(
        vocab=vocab,
        alert=alert,
        shape=_SHAPE_CONF if ask_confidence else _SHAPE,
        extra_rules=_CONF_RULE if ask_confidence else "",
    )


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
@functools.lru_cache(maxsize=2)
def load_vocab(which: str = "all") -> Tuple[Dict[str, str], Dict[str, List[str]], frozenset]:
    """Return (id->name, id->tactics, valid_ids).

    `which` selects only what the prompt SHOWS ("all" = 697, "parents" = 222);
    `valid_ids` is always the full v19.1 id set, because an answer is in-vocabulary
    if ATT&CK knows the id, regardless of which subset we displayed.

    Cached: the files are read-only at runtime. Returns immutable-ish shared dicts —
    callers must not mutate them.
    """
    with open(VOCAB_ALL, encoding="utf-8") as f:
        allv = json.load(f)                              # {id: {name, tactics}}
    tactics = {k: v.get("tactics", []) for k, v in allv.items()}
    if which == "parents":
        with open(VOCAB_PAR, encoding="utf-8") as f:
            names = json.load(f)                         # {id: name}
    else:
        names = {k: v["name"] for k, v in allv.items()}
    return names, tactics, frozenset(allv.keys())


@functools.lru_cache(maxsize=2)
def vocab_string(which: str = "all") -> str:
    """The "id: name" block inserted into the prompt, sorted for a stable prompt hash."""
    names, _, _ = load_vocab(which)
    return "\n".join(f"{tid}: {names[tid]}" for tid in sorted(names))


def technique_name(technique_id: str) -> str:
    """Canonical ATT&CK name for an id, falling back to the parent, then the id itself.

    Names come from the vocabulary rather than from the model's answer, so a model that
    pairs a right id with a wrong name cannot poison the audit trail.
    """
    names, _, _ = load_vocab("all")
    return names.get(technique_id) or names.get(technique_id.split(".")[0]) or technique_id


# ---------------------------------------------------------------------------
# Response parsing
#
# Deliberately forgiving: a strict json.loads throws away answers that are correct but
# wrapped in prose or fences, which shows up as a silent accuracy loss rather than as
# an error. Every relaxation is recorded on the result so callers can tell a clean
# answer from a salvaged one.
# ---------------------------------------------------------------------------
_TCODE = re.compile(r"T\d{4}(?:\.\d{3})?")
_THINK = re.compile(r"<(think|thinking|reasoning)>.*?(</\1>|\Z)", re.S)


def strip_think(s: str) -> str:
    """Drop inline thinking blocks: their candidate IDs are not the model's answer."""
    return _THINK.sub("", s).strip()


def parse_prediction(raw: str, reasoning: str = "") -> Dict:
    """Return {ranked, technique_id, confidence, reasoning, json_valid, parse_ok,
    from_reasoning}.

    `ranked` is the ordered list of predicted technique IDs (deduped, order kept);
    `technique_id` is the top-1 (kept for OOV/json/tactic single-pick metrics).
    `reasoning` (the argument) is the separate thinking channel, used only as a last
    resort when the answer channel is empty (thinking model truncated before its final
    message); such rows are flagged `from_reasoning` and never counted as valid JSON.
    """
    out = {"ranked": [], "technique_id": None, "confidence": None, "reasoning": "",
           "json_valid": False, "parse_ok": False, "from_reasoning": False}
    body = strip_think(raw)
    s = body
    if s.startswith("```"):
        s = s.split("```")[1] if len(s.split("```")) > 1 else s
        if s.startswith("json"):
            s = s[4:]
    s = s.strip()
    ranked: List[str] = []
    try:
        obj = json.loads(s)
        out["json_valid"] = True
        for t in (obj.get("techniques") or []):
            if isinstance(t, str) and t.strip():
                ranked.append(t.strip())
        conf = obj.get("confidence")
        if isinstance(conf, (int, float)):
            out["confidence"] = max(0.0, min(1.0, float(conf)))
        if isinstance(obj.get("reasoning"), str):
            out["reasoning"] = obj["reasoning"]
    except Exception:
        pass
    if not ranked:                                    # fallback: all T-codes in text, in order
        ranked = _TCODE.findall(body)
    # dedup, preserve order
    seen, deduped = set(), []
    for t in ranked:
        if t not in seen:
            seen.add(t); deduped.append(t)
    out["ranked"] = deduped
    out["technique_id"] = deduped[0] if deduped else None
    out["parse_ok"] = out["technique_id"] is not None
    if not out["ranked"] and reasoning.strip():
        # answer channel empty -> salvage from the thinking channel, flagged as such
        alt = parse_prediction(reasoning)
        if alt["ranked"]:
            alt["json_valid"] = False
            alt["from_reasoning"] = True
            return alt
    return out


def in_vocab(ranked: List[str], valid_ids: Optional[frozenset] = None) -> List[str]:
    """Filter predicted ids down to those ATT&CK v19.1 actually defines, order kept.

    Models routinely emit ids recalled from their weights instead of selecting from the
    candidate list (the evaluator reports this as OOV%); such ids cannot be looked up in
    the playbook library and must not reach the audit trail as if they were real.
    """
    if valid_ids is None:
        _, _, valid_ids = load_vocab("all")
    return [t for t in ranked if t in valid_ids]

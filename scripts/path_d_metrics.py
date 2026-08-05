#!/usr/bin/env python3
"""
Automatic, reference-free scoring for generated CACAO playbooks (Path D / RQ2).

There is no ground-truth playbook for the 37-alert benchmark and nothing from
playbooks/ is consulted, so every metric here is either
  (a) a property of the artifact itself   — spec compliance, graph shape, syntax, or
  (b) a relation between the artifact and the alert it came from — IOC grounding.

Metric groups (see score_playbook):
  parse       json_valid, parse_ok, from_reasoning
  spec        5-bucket verifier score + per-severity issue COUNTS. The counts matter:
              PlaybookVerifier aggregates with min(), so overall_score only reports the
              single worst issue and cannot separate one bad step from ten.
  structural  is_dag, has_end, end_reachable, orphan/dangling counts
  content     unfilled scaffold text, command counts, `bash -n` syntax validity
  grounding   ioc_recall / ioc_in_commands, and hallucinated IPs (indicators the model
              invented that the alert never mentioned)
  safety      destructive_rate, from core/playbook_verification/policy.py — that file is
              the ruleset's owner and the extension point; nothing here defines rules
"""

import functools
import glob
import ipaddress
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.playbook_verification.policy import policy_violations
from core.playbook_verification.verifier import (
    PlaybookVerifier, VerificationScore, cacao_to_verifier_nodes,
)
from utils.llm.playbook import (
    COMMAND_TYPES, REQUIRED_FIELDS, STEP_TYPES, all_text, iter_commands,
    iter_commands_typed,
)

_STEP_ID  = re.compile(r"^step--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_IDENT_ID = re.compile(r"^identity--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TS       = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def cacao_conformance(pb: Dict) -> Dict:
    """Score a playbook against CACAO 2.0 itself, not against core's verifier."""
    wf = pb.get("workflow") if isinstance(pb.get("workflow"), dict) else {}
    steps = [(sid, st) for sid, st in wf.items() if isinstance(st, dict)]
    cmds: List[Dict] = []
    for _sid, st in steps:
        for c in (st.get("commands") or []):
            if isinstance(c, dict):
                cmds.append(c)

    def frac(items, pred) -> float:
        items = list(items)
        return 1.0 if not items else sum(1 for i in items if pred(i)) / len(items)

    action_steps = [st for _s, st in steps if st.get("type") == "action"]
    refs = [(st, k) for _s, st in steps
            for k in ("on_success", "on_failure", "on_completion", "on_true", "on_false")
            if isinstance(st.get(k), str)]
    start_id = pb.get("workflow_start")

    cats = [
        ("required_properties", frac(REQUIRED_FIELDS, lambda f: f in pb), True),
        ("type_literal",        1.0 if pb.get("type") == "playbook" else 0.0, True),
        ("spec_version",        1.0 if pb.get("spec_version") == "cacao-2.0" else 0.0, True),
        ("id_format",           1.0 if _UUID_ID.match(str(pb.get("id", ""))) else 0.0, True),
        ("created_by_format",   1.0 if _IDENT_ID.match(str(pb.get("created_by", ""))) else 0.0, True),
        ("timestamps",          frac(("created", "modified"),
                                     lambda f: bool(_TS.match(str(pb.get(f, ""))))), True),
        ("workflow_present",    1.0 if wf else 0.0, True),
        ("workflow_start_ok",   1.0 if start_id in wf else 0.0, True),
        ("step_types",          frac(steps, lambda p: p[1].get("type") in STEP_TYPES), True),
        ("action_has_commands", frac(action_steps, lambda st: bool(st.get("commands"))), True),
        ("command_types",       frac(cmds, lambda c: c.get("type") in COMMAND_TYPES), True),
        ("command_nonempty",    frac(cmds, lambda c: bool(str(c.get("command", "")).strip())), True),
        ("reference_integrity", frac(refs, lambda r: r[0].get(r[1]) in wf), True),
        ("has_end",             1.0 if any(st.get("type") == "end" for _s, st in steps) else 0.0, True),
        ("step_id_format",      frac(steps, lambda p: bool(_STEP_ID.match(str(p[0])))), False),
    ]

    errs = [n for n, sc, hard in cats if hard and sc < 1.0]
    warns = [n for n, sc, hard in cats if not hard and sc < 1.0]
    conformance = 100.0 * sum(sc for _n, sc, _h in cats) / len(cats)
    bad_types = sorted({str(st.get("type")) for _s, st in steps
                        if st.get("type") not in STEP_TYPES})
    return {
        "cacao_valid":      not errs,
        "conformance":      round(conformance, 1),
        "failed_categories": errs + [f"{w} (style)" for w in warns],
        "bad_step_types":   bad_types,
        "n_bad_step_types": sum(1 for _s, st in steps if st.get("type") not in STEP_TYPES),
        "missing_fields":   sum(1 for f in REQUIRED_FIELDS if f not in pb),
        "missing_names":    [f for f in REQUIRED_FIELDS if f not in pb],
    }


# Official CACAO 2.0 schema validation
SCHEMA_DIR = os.path.join(ROOT, "data", "cacao-schemas")


@functools.lru_cache(maxsize=1)
def _schema_validator():
    """Draft-7 validator for playbook.json with all 51 $ref'd schemas preloaded.

    Returns None (rather than raising) if jsonschema or the vendored schemas are absent,
    so the evaluator degrades to our own checks instead of failing the whole run.
    """
    try:
        from jsonschema import Draft7Validator, RefResolver
    except ImportError:
        return None
    entry = os.path.join(SCHEMA_DIR, "playbook.json")
    if not os.path.exists(entry):
        return None
    with open(entry, encoding="utf-8") as f:
        schema = json.load(f)
    store = {}
    for path in glob.glob(os.path.join(SCHEMA_DIR, "**", "*.json"), recursive=True):
        try:
            with open(path, encoding="utf-8") as f:
                sub = json.load(f)
        except Exception:
            continue
        if isinstance(sub, dict) and "$id" in sub:
            store[sub["$id"]] = sub
    resolver = RefResolver(base_uri=schema.get("$id", "file://" + SCHEMA_DIR + "/"),
                           referrer=schema, store=store)
    return Draft7Validator(schema, resolver=resolver)


def cacao_schema_check(pb: Dict) -> Dict:
    """Validate against the official OASIS CACAO 2.0 schemas."""
    v = _schema_validator()
    if v is None:
        return {"schema_valid": None, "n_schema_errors": None, "schema_errors": [],
                "schema_available": False}
    try:
        errs = sorted(v.iter_errors(pb), key=lambda e: list(e.path))
    except Exception as exc:
        return {"schema_valid": False, "n_schema_errors": None,
                "schema_errors": [f"validator error: {type(exc).__name__}: {exc}"],
                "schema_available": True}
    return {
        "schema_valid":     not errs,
        "n_schema_errors":  len(errs),
        "schema_errors":    [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message[:120]}"
                             for e in errs[:8]],
        "schema_available": True,
    }


# Declared MITRE technique
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def declared_technique(pb: Dict) -> Optional[str]:
    """The ATT&CK id the playbook claims to respond to, or None if it declared none."""
    refs = pb.get("external_references")
    if isinstance(refs, dict):
        refs = [refs]
    for ref in (refs or []):
        if not isinstance(ref, dict):
            continue
        src = str(ref.get("source") or ref.get("source_name") or "").lower()
        if "mitre" not in src and "attack" not in src:
            continue
        for field in ("external_id", "name", "description", "url"):
            m = _TID.search(str(ref.get(field, "")))
            if m:
                return m.group(0)
    return None


def technique_match(pb: Dict, gt: Dict) -> Dict:
    """Compare the declared id against the benchmark label at parent and exact level.

    Reported as a share of alerts where the model declared an id AND it matched, so a
    model that declines to declare is not rewarded for silence.
    """
    declared = declared_technique(pb)
    if not declared:
        return {"declared": None, "tech_declared": False,
                "tech_parent_ok": False, "tech_exact_ok": False}
    return {
        "declared":       declared,
        "tech_declared":  True,
        "tech_parent_ok": declared.split(".")[0] in set(gt.get("technique_parents") or []),
        "tech_exact_ok":  declared in set(gt.get("technique_ids") or []),
    }


_UUID_ID  = re.compile(r"^playbook--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_UNFILLED = [
    re.compile(r"<fill:[^>]*>", re.I),
    re.compile(r"\{\{\s*\w+\s*\}\}"),
    re.compile(r"\bTODO\b|\bFIXME\b|\bXXX\b"),
    re.compile(r"<(?:your|the|insert|add|specify)[^>]{0,40}>", re.I),
]

# IOC extraction from alert TEXT
_IPV4     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN   = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"(?:com|net|org|ru|cn|info|biz|top|xyz|io|co|de|uk|fr|nl|pw|cc|tk|onion)\b", re.I)
_URLPATH  = re.compile(r"https?://\S+|/(?=[A-Za-z0-9_\-./]*[A-Za-z]{3})[A-Za-z0-9_\-./]{4,}")
_PORT     = re.compile(r"port\s*[:=]\s*(\d{2,5})", re.I)
_USER     = re.compile(r"(?:\buser(?:name)?|\bdstuser|\bsrcuser|\baccount)\s*[:=]\s*"
                       r"([A-Za-z0-9._\-\\$]{2,40})", re.I)
_UA       = re.compile(r"user[_-]?agent\s*[:=]\s*(.+)", re.I)
_PROC     = re.compile(r"(?:\bprocess|\bimage|\bexe)\s*[:=]\s*"
                       r"([A-Za-z0-9_\-.]+\.(?:exe|sh|py|dll|bin))", re.I)

_UA_GENERIC = {"mozilla", "windows", "macintosh", "compatible", "msie", "gecko",
               "khtml", "chrome", "safari", "applewebkit", "linux", "x11", "trident",
               "version", "like", "intel", "mac", "os", "wow64", "nt", "edge",
               "firefox", "opera", "android", "iphone", "mobile"}


def _is_routable(ip: str) -> bool:
    """True for a real public address — private/loopback/doc ranges are not indicators."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved
                or a.is_link_local or a.is_unspecified)


def extract_iocs(alert_text: str) -> Dict[str, Set[str]]:
    """Indicators mentioned by the alert, by kind. Values are the literal strings a
    playbook would have to contain to be about this alert."""
    t = alert_text
    iocs: Dict[str, Set[str]] = {
        "ip":     {m for m in _IPV4.findall(t)},
        "domain": {m.lower() for m in _DOMAIN.findall(t)},
        "url":    {m for m in _URLPATH.findall(t) if len(m) > 4},
        "port":   set(_PORT.findall(t)),
        "user":   {m for m in _USER.findall(t) if m.lower() not in ("agent", "name")},
        "proc":   {m for m in _PROC.findall(t)},
    }
    ua = _UA.search(t)
    iocs["ua_token"] = set()
    if ua:
        for tok in re.findall(r"[A-Za-z][A-Za-z0-9]{3,}", ua.group(1)):
            if tok.lower() not in _UA_GENERIC:
                iocs["ua_token"] = {tok}
                break
    return {k: v for k, v in iocs.items() if v}


def _bash_syntax_ok(cmd: str) -> bool:
    """Syntax-check with `bash -n`. Parses only — never executes."""
    try:
        p = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, timeout=10)
        return p.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


# Per-command-type validation
_HTTP_LINE = re.compile(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", re.I)


def validate_command(ctype: str, cmd: str) -> Optional[bool]:
    """True = valid, False = invalid, None = no local validator for this type."""
    t = (ctype or "").lower()
    if t in ("bash", "ssh"):          # ssh carries a shell command to a remote host
        return _bash_syntax_ok(cmd)
    if t in ("http-api", "openc2-http"):
        m = _HTTP_LINE.search(cmd)
        if m:                          # "POST /v1/block HTTP/1.1" or a full URL
            return True
        return cmd.strip().startswith(("http://", "https://", "{"))
    if t == "powershell":
        # no parser available here; balanced quotes/braces is the most we can assert
        return cmd.count('"') % 2 == 0 and cmd.count("{") == cmd.count("}")
    if t in ("sigma", "yara", "elastic", "kestrel", "caldera-cmd", "jupyter"):
        return None                    # domain-specific grammars, not checked here
    if t == "manual":
        return None                    # an instruction for a human, not a command
    return None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score_playbook(playbook: Dict, alert_text: str, check_bash: bool = True) -> Dict:
    """Every automatic metric for one generated playbook. Never raises."""
    out: Dict = {}
    verifier = PlaybookVerifier()

    # independent CACAO 2.0 conformance (see cacao_conformance) — reported alongside the
    # repo verifier's score, never instead of it
    out.update(cacao_conformance(playbook))
    out.update(cacao_schema_check(playbook))

    # --- spec + structural, via the production verifier (structural_only: no judge here)
    try:
        res = verifier.verify(playbook, structural_only=True, is_template=False)
        issues = res["issues"]
        out["spec_score"]  = res["overall_score"]
        out["spec_passed"] = res["passed"]
        out["spec_clean"]  = res["overall_score"] == VerificationScore.NO_ERROR.value
    except Exception as exc:
        issues = []
        out["spec_score"], out["spec_passed"], out["spec_clean"] = 0, False, False
        out["verify_error"] = f"{type(exc).__name__}: {exc}"

    by_sev = {"critical": 0, "major": 0, "moderate": 0, "minor": 0}
    for i in issues:
        for name, val in (("critical", 20), ("major", 40), ("moderate", 60), ("minor", 80)):
            if i["score"] == val:
                by_sev[name] += 1
    out.update({f"n_{k}": v for k, v in by_sev.items()})
    out["n_issues"]   = len(issues)
    out["n_errors"]   = sum(1 for i in issues if i["severity"] == "error")
    out["issue_desc"] = [i["description"] for i in issues[:8]]

    # --- required fields / id format
    missing = [f for f in REQUIRED_FIELDS if f not in playbook]
    out["missing_fields"]   = len(missing)
    out["missing_names"]    = missing
    out["id_format_ok"]     = bool(_UUID_ID.match(str(playbook.get("id", ""))))
    out["spec_version_ok"]  = playbook.get("spec_version") == "cacao-2.0"

    # --- graph shape
    workflow = playbook.get("workflow") or {}
    out["n_steps"] = len(workflow)
    step_types = [s.get("type") for s in workflow.values() if isinstance(s, dict)]
    out["has_end"] = "end" in step_types
    dangling = 0
    for step in workflow.values():
        if not isinstance(step, dict):
            continue
        for key in ("on_success", "on_failure", "on_completion"):
            tgt = step.get(key)
            if tgt and tgt not in workflow:
                dangling += 1
    out["n_dangling_refs"] = dangling

    try:
        import networkx as nx
        G = nx.DiGraph()
        for sid in workflow:
            G.add_node(sid)
        for sid, step in workflow.items():
            if not isinstance(step, dict):
                continue
            for key in ("on_success", "on_failure", "on_completion", "on_true", "on_false"):
                tgt = step.get(key)
                if isinstance(tgt, str):
                    G.add_edge(sid, tgt)
                elif isinstance(tgt, list):
                    for t in tgt:
                        if isinstance(t, str):
                            G.add_edge(sid, t)
            for t in (step.get("next_steps") or []):
                if isinstance(t, str):
                    G.add_edge(sid, t)
            cases = step.get("cases")
            if isinstance(cases, dict):
                for tgts in cases.values():
                    for t in ([tgts] if isinstance(tgts, str) else (tgts or [])):
                        if isinstance(t, str):
                            G.add_edge(sid, t)
        out["is_dag"] = nx.is_directed_acyclic_graph(G) if G.number_of_nodes() else False
        start = playbook.get("workflow_start")
        ends  = [sid for sid, s in workflow.items()
                 if isinstance(s, dict) and s.get("type") == "end"]
        out["end_reachable"] = bool(
            start in G and ends and any(nx.has_path(G, start, e) for e in ends if e in G)
        )
        out["n_orphan_steps"] = sum(
            1 for n in G.nodes
            if n != start and G.in_degree(n) == 0
        )
    except Exception:
        out["is_dag"], out["end_reachable"], out["n_orphan_steps"] = False, False, 0

    # --- content substance
    text  = all_text(playbook)
    cmds  = iter_commands_typed(playbook)
    out["n_commands"] = len(cmds)
    action_steps = [s for s in workflow.values()
                    if isinstance(s, dict) and s.get("type") not in ("end", "start")]
    with_cmd = sum(1 for s in action_steps if (s.get("commands") or []))
    out["frac_steps_with_command"] = (with_cmd / len(action_steps)) if action_steps else 0.0
    out["n_unfilled"] = sum(len(p.findall(text)) for p in _UNFILLED)
    out["cmd_chars"]  = sum(len(c) for _sid, _t, c in cmds)

    checkable, ok_cmds, unvalidated = 0, 0, 0
    for _sid, ctype, c in cmds:
        verdict = validate_command(ctype, c) if check_bash else None
        clean = not any(p.search(c) for p in _UNFILLED)
        if verdict is None:
            unvalidated += 1
            continue
        checkable += 1
        if verdict and clean:
            ok_cmds += 1
    out["n_checkable_cmds"] = checkable
    out["n_unvalidated_cmds"] = unvalidated
    out["exec_rate"] = (ok_cmds / checkable) if checkable else None
    out["cmd_types"] = sorted({t for _s, t, _c in cmds})

    # safety policy (pattern-based; destined for the Playbook Verification component)
    viol = {}
    for _sid, _t, c in cmds:
        for name in policy_violations(c):
            viol[name] = viol.get(name, 0) + 1
    n_bad_cmds = sum(1 for _sid, _t, c in cmds if policy_violations(c))
    out["n_policy_violations"] = sum(viol.values())
    out["policy_rules_hit"]    = sorted(viol)
    out["destructive_rate"]    = (n_bad_cmds / len(cmds)) if cmds else None

    # --- grounding against the alert
    iocs = extract_iocs(alert_text)
    flat = {v for vals in iocs.values() for v in vals}
    cmd_text = "\n".join(c for _sid, _t, c in cmds)
    hit_any  = {v for v in flat if v.lower() in text.lower()}
    hit_cmd  = {v for v in flat if v.lower() in cmd_text.lower()}
    out["n_iocs"]          = len(flat)
    out["ioc_recall"]      = len(hit_any) / len(flat) if flat else None
    out["ioc_in_commands"] = len(hit_cmd) / len(flat) if flat else None
    out["ioc_missed"]      = sorted(flat - hit_any)[:6]

    alert_ips = {m for m in _IPV4.findall(alert_text)}
    pb_ips    = {m for m in _IPV4.findall(text)}
    invented  = {ip for ip in pb_ips - alert_ips if _is_routable(ip)}
    out["n_hallucinated_ip"] = len(invented)      # computed, not scored in the table
    out["hallucinated_ips"]  = sorted(invented)[:6]

    # flow%: the graph tier as ONE number. All four must hold — is_dag alone passes a
    # workflow whose end step is unreachable.
    out["flow_ok"] = bool(out.get("is_dag") and out.get("end_reachable")
                          and not out.get("n_orphan_steps")
                          and not out.get("n_dangling_refs"))

    return out


def empty_score(reason: str) -> Dict:
    """Score row for a response that produced no playbook — keeps table columns aligned."""
    return {"cacao_valid": False, "conformance": 0.0, "n_spec_errors": 0,
            "n_spec_warnings": 0, "spec_errors": [reason], "bad_step_types": [],
            "n_bad_step_types": 0,
            "spec_score": 0, "spec_passed": False, "spec_clean": False,
            "n_critical": 0, "n_major": 0, "n_moderate": 0, "n_minor": 0,
            "n_issues": 0, "n_errors": 0, "issue_desc": [reason],
            "missing_fields": len(REQUIRED_FIELDS), "missing_names": list(REQUIRED_FIELDS),
            "id_format_ok": False, "spec_version_ok": False,
            "n_steps": 0, "has_end": False, "n_dangling_refs": 0,
            "is_dag": False, "end_reachable": False, "n_orphan_steps": 0,
            "n_commands": 0, "frac_steps_with_command": 0.0, "n_unfilled": 0,
            "cmd_chars": 0, "bash_ok": 0, "bash_rate": 0.0,
            "n_iocs": 0, "ioc_recall": None, "ioc_in_commands": None, "ioc_missed": [],
            "n_hallucinated_ip": 0, "hallucinated_ips": []}

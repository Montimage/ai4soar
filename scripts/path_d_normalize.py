#!/usr/bin/env python3
"""
Identifier-normalisation ablation for Path D (RQ2).

Why this exists
---------------
Every CACAO 2.0 schema violation observed in scripts/evaluate_path_d.py is an
identifier-format error: models emit hex-shaped placeholders such as
`identity--12345678-90ab-cdef-1234-567890abcdef` or `step--11111111-2222-3333-4444-...`
that are not RFC 4122 UUIDs, so they fail the CACAO identifier pattern

    ^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}
     -[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$

Examples
--------
  python3 scripts/path_d_normalize.py
  python3 scripts/path_d_normalize.py --models qwen3.6:35b,gpt-oss:20b
  python3 scripts/path_d_normalize.py --show-mapping 3      # inspect the rewrites
"""

import argparse
import collections
import copy
import json
import os
import re
import statistics
import sys
import uuid
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.path_d_metrics import score_playbook

TESTSET = os.path.join(ROOT, "datasets", "eval", "alert_benchmark_eval.jsonl")
OUT_DIR = os.path.join(ROOT, "output", "path_d_eval")

# The CACAO identifier grammar, lifted from data/cacao-schemas/data-types/identifier.json
CACAO_ID = re.compile(
    r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
# Anything shaped like `object-type--<something>`; the something need not be a valid UUID,
# which is precisely the case we are here to repair.
ID_SHAPED = re.compile(r"^([a-z][a-z0-9-]*[a-z0-9])--(.+)$")

# Fixed namespace so the rewrite is reproducible across runs and machines.
NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def repair_identifier(ident: str) -> str:
    """`type--<junk>` -> `type--<deterministic RFC 4122 UUIDv5>`, prefix preserved.

    uuid5 sets the version nibble to 5 (inside the [1-5] the pattern demands) and the
    variant bits to 10x (giving a 4th group starting 8/9/a/b), so the result is compliant
    by construction rather than by luck.
    """
    m = ID_SHAPED.match(ident)
    if not m:
        return ident
    prefix = m.group(1)
    return f"{prefix}--{uuid.uuid5(NS, ident)}"


def collect_malformed(node, found: Dict[str, str]) -> None:
    """Walk the playbook and record every identifier-shaped string that fails the pattern.

    Dict KEYS matter as much as values: the `workflow` map is keyed by step identifier, so
    a rewrite that only touched values would leave the keys dangling.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and ID_SHAPED.match(k) and not CACAO_ID.match(k):
                found.setdefault(k, repair_identifier(k))
            collect_malformed(v, found)
    elif isinstance(node, list):
        for v in node:
            collect_malformed(v, found)
    elif isinstance(node, str):
        if ID_SHAPED.match(node) and not CACAO_ID.match(node):
            found.setdefault(node, repair_identifier(node))


def substitute(node, mapping: Dict[str, str]):
    """Rebuild the structure with every mapped identifier replaced, keys included."""
    if isinstance(node, dict):
        return {mapping.get(k, k) if isinstance(k, str) else k: substitute(v, mapping)
                for k, v in node.items()}
    if isinstance(node, list):
        return [substitute(v, mapping) for v in node]
    if isinstance(node, str):
        return mapping.get(node, node)
    return node


def step_key_mapping(pb: Dict) -> Dict[str, str]:
    """Map every workflow step key to `<step type>--<deterministic UUID>`.

    CACAO requires the identifier prefix to equal the object's own `type` value, so an
    action step must be keyed `action--<uuid>`, not `step--<uuid>`. playbook.json enforces
    this with patternProperties over the eight step types plus
    `unevaluatedProperties: false`, which means a `step--` key is not merely ugly: it
    fails validation AND prevents the step schema's $ref from ever applying, leaving the
    step body unchecked.

    Every model in this benchmark uses `step--` for 100% of its keys while labelling each
    step object with the correct `type`, so the repair needs no inference: the right prefix
    is already present in the playbook.
    """
    mapping: Dict[str, str] = {}
    for key, step in (pb.get("workflow") or {}).items():
        if not isinstance(key, str) or not ID_SHAPED.match(key):
            continue
        stype = (step or {}).get("type") if isinstance(step, dict) else None
        if not isinstance(stype, str) or not re.match(r"^[a-z][a-z0-9-]*[a-z0-9]$", stype):
            continue                      # no usable type: leave it for the UUID-only pass
        mapping[key] = f"{stype}--{uuid.uuid5(NS, key)}"
    return mapping


def normalise(pb: Dict) -> Tuple[Dict, Dict[str, str]]:
    """Two-part repair: step keys get the correct type prefix, and any remaining
    identifier-shaped string that violates the grammar gets a compliant UUID."""
    mapping = step_key_mapping(pb)
    residual: Dict[str, str] = {}
    collect_malformed(pb, residual)
    for old, new in residual.items():
        mapping.setdefault(old, new)      # step-key rewrites win over UUID-only rewrites
    return (substitute(copy.deepcopy(pb), mapping) if mapping else pb), mapping


def mean(vals) -> float:
    vals = [v for v in vals if v is not None]
    return statistics.fmean(vals) if vals else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure schema conformance after a "
                                             "deterministic identifier rewrite")
    ap.add_argument("--models", default="", help="comma-separated subset (default: all)")
    ap.add_argument("--mode", default="schema")
    ap.add_argument("--detail", default=os.path.join(OUT_DIR, "results_detail.jsonl"))
    ap.add_argument("--testset", default=TESTSET)
    ap.add_argument("--out", default=os.path.join(OUT_DIR, "normalised.jsonl"),
                    help="written separately; the main results file is never modified")
    ap.add_argument("--show-mapping", type=int, default=0,
                    help="print the rewrites for the first N repaired playbooks")
    ap.add_argument("--no-bash-check", action="store_true")
    args = ap.parse_args()

    texts = {}
    for line in open(args.testset):
        line = line.strip()
        if line:
            row = json.loads(line)
            texts[row["id"]] = row["text"]["visible"]

    wanted = {m.strip() for m in args.models.split(",")} if args.models else None
    rows = []
    for line in open(args.detail):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r["mode"] != args.mode or r.get("error") or not r.get("playbook"):
            continue
        if wanted and r["model"] not in wanted:
            continue
        rows.append(r)

    if not rows:
        print("no parsed playbooks matched — check --models / --mode / --detail")
        return

    print(f"playbooks: {len(rows)}  models: {sorted({r['model'] for r in rows})}")
    print("re-scoring cached playbooks only — no model calls\n")

    out_fp = open(args.out, "w")
    results = []
    shown = 0
    for r in rows:
        text = texts.get(r["alert_id"], "")
        pb_norm, mapping = normalise(r["playbook"])
        after = score_playbook(pb_norm, text, check_bash=not args.no_bash_check)
        if mapping and shown < args.show_mapping:
            print(f"--- {r['model']} / {r['alert_id'][:44]}  ({len(mapping)} rewrites)")
            for old, new in list(mapping.items())[:6]:
                print(f"    {old}\n     -> {new}")
            shown += 1
        rec = {
            "model": r["model"], "alert_id": r["alert_id"], "rep": r.get("rep", 0),
            "n_rewritten": len(mapping),
            "schema_before": r.get("schema_valid"), "schema_after": after["schema_valid"],
            "flow_before": r.get("flow_ok"),        "flow_after": after["flow_ok"],
            "exec_before": r.get("exec_rate"),      "exec_after": after["exec_rate"],
            "cacao_before": r.get("conformance"),   "cacao_after": after["conformance"],
            "steps_before": r.get("n_steps"),       "steps_after": after["n_steps"],
            "errors_after": after.get("schema_errors") or [],
        }
        results.append(rec)
        out_fp.write(json.dumps(rec, default=str) + "\n")
    out_fp.close()

    agg = collections.defaultdict(list)
    for rec in results:
        agg[rec["model"]].append(rec)

    print("=" * 104)
    print(f"{'model':20s} {'n':>4s} {'rewr/pb':>8s} "
          f"{'Schema':>7s} {'->':>7s} {'Flow':>7s} {'->':>7s} {'Exec':>7s} {'->':>7s} "
          f"{'residual':>9s}")
    print("-" * 104)
    for m, rs in sorted(agg.items()):
        n = len(rs)
        def pct(f): return 100.0 * sum(1 for r in rs if r[f]) / n
        residual = sum(1 for r in rs if not r["schema_after"])
        print(f"{m:20s} {n:4d} {mean(r['n_rewritten'] for r in rs):8.1f} "
              f"{pct('schema_before'):7.1f} {pct('schema_after'):7.1f} "
              f"{pct('flow_before'):7.1f} {pct('flow_after'):7.1f} "
              f"{100 * mean(r['exec_before'] for r in rs):7.1f} "
              f"{100 * mean(r['exec_after'] for r in rs):7.1f} "
              f"{residual:9d}")
    print("=" * 104)
    print("Schema/Flow/Exec are shown before -> after the identifier rewrite.\n"
          "residual = playbooks still failing the official schemas after normalisation;\n"
          "           these are the violations that are NOT identifier-format\n"
          "A rise in Schema with Flow unchanged is the result that supports the claim:\n"
          "the rewrite fixes conformance without breaking referential integrity. Any drop\n"
          "in Flow means the substitution missed a reference site and the claim fails.")

    broke = [r for r in results if r["flow_before"] and not r["flow_after"]]
    if broke:
        print(f"\nWARNING {len(broke)} playbooks had sound flow before normalisation and "
              f"broken flow after -> the rewrite is missing a reference site:")
        for r in broke[:5]:
            print(f"  {r['model']} {r['alert_id'][:50]} ({r['n_rewritten']} rewrites)")

    residual_errs = collections.Counter()
    for r in results:
        if not r["schema_after"]:
            for e in r["errors_after"]:
                residual_errs[str(e).split(":")[0].strip()] += 1
    if residual_errs:
        print(f"\nresidual violation fields: {residual_errs.most_common(8)}")

    print(f"\nper-playbook detail: {args.out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Path D evaluator — LLMs generating CACAO 2.0 playbooks from a raw alert (RQ2).

What it does
------------
For each of the 37 benchmark alerts (visible view), asks each model to produce an
executable CACAO 2.0 playbook, then scores the result with reference-free automatic
metrics. Nothing from playbooks/ is shown to the model and no ground-truth playbook is
consulted: the playbook must come from the model's own knowledge plus the alert.

Modes (utils/llm/playbook.py)
-----------------------------
  free      spec knowledge only, no field list, no structure
  schema    required fields + linking rules, model chooses the workflow shape
  skeleton  fixed 5-step scaffold, model fills descriptions and commands

Structural metrics are informative in free/schema and vacuous in skeleton (the scaffold
guarantees them), which is the point of comparing the three.

Examples
--------
  # smoke test: 3 alerts, one cheap model, all three modes
  python3 scripts/evaluate_path_d.py --limit 3 --models claude-haiku-4-5 --mode all

  # pilot: full benchmark, 3 models, 3 modes
  python3 scripts/evaluate_path_d.py --models claude-haiku-4-5,gpt-4o-mini,llama3.1:8b \
      --mode all

  # re-score from cache without calling any model (e.g. after a metric change)
  python3 scripts/evaluate_path_d.py --score-only

  # render the prompts and self-test the scorer, no API calls, no cost
  python3 scripts/evaluate_path_d.py --dry-run
"""

import argparse
import collections
import hashlib
import json
import os
import statistics
import sys
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.path_d_metrics import (
    empty_score, extract_iocs, score_playbook, technique_match,
)
from utils.llm.client import call_model
from utils.llm.playbook import MODES, build_prompt, build_skeleton, parse_playbook

TESTSET = os.path.join(ROOT, "datasets", "eval", "alert_benchmark_eval.jsonl")
OUT_DIR = os.path.join(ROOT, "output", "path_d_eval")

MAX_TOKENS      = 8192
DEFAULT_NUM_CTX = 16384
THINK_TOKENS    = 24576
THINK_NUM_CTX   = 32768

MODELS: List[Dict] = [
    {"name": "gpt-4o-mini",       "provider": "openai",    "model": "gpt-4o-mini",       "price": (0.15, 0.60)},
    {"name": "gpt-4.1",           "provider": "openai",    "model": "gpt-4.1",           "price": (2.00, 8.00)},
    {"name": "gpt-5-mini",        "provider": "openai",    "model": "gpt-5-mini",        "price": (0.25, 2.00), "max_tokens": 24000},
    {"name": "gpt-5",             "provider": "openai",    "model": "gpt-5",             "price": (1.25, 10.0), "reasoning_effort": "medium", "max_tokens": 24000},
    {"name": "gpt-5-low",         "provider": "openai",    "model": "gpt-5",             "price": (1.25, 10.0), "reasoning_effort": "minimal", "max_tokens": 24000},
    {"name": "claude-haiku-4-5",  "provider": "anthropic", "model": "claude-haiku-4-5",  "price": (1.00, 5.00)},
    {"name": "claude-sonnet-5",   "provider": "anthropic", "model": "claude-sonnet-5",   "price": (3.00, 15.0)},
    {"name": "claude-opus-4-8",   "provider": "anthropic", "model": "claude-opus-4-8",   "price": (5.00, 25.0)},
    {"name": "llama3.1:8b",       "provider": "ollama",    "model": "llama3.1:8b",       "price": (0, 0)},
    {"name": "llama3.2:3b",       "provider": "ollama",    "model": "llama3.2:3b",       "price": (0, 0)},
    {"name": "qwen2.5:0.5b",      "provider": "ollama",    "model": "qwen2.5:0.5b",      "price": (0, 0)},
    {"name": "gemma3:12b",        "provider": "ollama",    "model": "gemma3:12b",        "price": (0, 0)},
    {"name": "phi4:14b",          "provider": "ollama",    "model": "phi4:14b",          "price": (0, 0)},
    {"name": "mistral:7b",        "provider": "ollama",    "model": "mistral:7b",        "price": (0, 0)},
    {"name": "qwen3.6:35b",       "provider": "ollama",    "model": "qwen3.6:35b",       "price": (0, 0), "max_tokens": THINK_TOKENS, "num_ctx": THINK_NUM_CTX},
    {"name": "gpt-oss:20b",       "provider": "ollama",    "model": "gpt-oss:20b",       "price": (0, 0), "max_tokens": THINK_TOKENS, "num_ctx": THINK_NUM_CTX},
]


def call_spec(spec: Dict, prompt: str):
    resolved = {**spec,
                "max_tokens": spec.get("max_tokens", MAX_TOKENS),
                "num_ctx":    spec.get("num_ctx", DEFAULT_NUM_CTX)}
    return call_model(resolved, prompt)


def cache_key(model: str, mode: str, alert_id: str, prompt: str, rep: int,
              spec: Optional[Dict] = None) -> str:
    h = hashlib.sha1(prompt.encode()).hexdigest()[:8]
    base = f"{model}|{mode}|{alert_id}|{h}|r{rep}"
    if spec and spec["provider"] == "ollama":
        base += f"|ctx{spec.get('num_ctx', DEFAULT_NUM_CTX)}|out{spec.get('max_tokens', MAX_TOKENS)}"
    return base


def load_cache(path: str) -> Dict[str, Dict]:
    c: Dict[str, Dict] = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line:
                r = json.loads(line)
                c[r["key"]] = r
    return c


def load_alerts(path: str, limit: int, sample: int = 0) -> List[Dict]:
    """Load the benchmark, optionally stratified by sensor.

    --limit takes the first N, which on this benchmark means 8 MMT alerts before any
    Snort or Suricata row appears; --sample round-robins across meta.source_tool so a
    subset actually spans the three sensors.
    """
    rows = [json.loads(l) for l in open(path) if l.strip()]
    if sample:
        by: Dict[str, List[Dict]] = collections.defaultdict(list)
        for r in rows:
            by[(r.get("meta") or {}).get("source_tool", "?")].append(r)
        groups, picked, i = list(by.values()), [], 0
        while len(picked) < min(sample, len(rows)):
            g = groups[i % len(groups)]
            if g:
                picked.append(g.pop())
            i += 1
            if all(not g for g in groups):
                break
        rows = picked
    return rows[:limit] if limit else rows


def alert_text(row: Dict) -> str:
    """The visible view — at generation time an analyst has the whole alert."""
    return row["text"]["visible"]


def mean(vals) -> float:
    vals = [v for v in vals if v is not None]
    return statistics.fmean(vals) if vals else 0.0


# ---------------------------------------------------------------------------
# Dry run — validates prompts and the scorer without spending anything
# ---------------------------------------------------------------------------
def dry_run(alerts: List[Dict], modes: List[str]) -> None:
    a = alerts[0]
    print(f"=== prompt sizes (alert {a['id']}) ===")
    for m in modes:
        p = build_prompt(alert_text(a), m)
        print(f"  {m:9s} {len(p):6d} chars  ~{int(len(p)/3.5):5d} tokens")
    print(f"\n=== prompt: mode=schema ===\n{build_prompt(alert_text(a), 'schema')}\n")

    print("=== IOCs extracted from each alert ===")
    for r in alerts:
        iocs = extract_iocs(alert_text(r))
        flat = sorted({v for vs in iocs.values() for v in vs})
        print(f"  {r['id'][:44]:44s} {len(flat):2d}  {flat[:6]}")

    print("\n=== scorer self-test ===")
    good = build_skeleton()
    for sid, step in good["workflow"].items():
        if step.get("type") == "end":
            continue
        step["name"] = "Block source"
        step["description"] = "Block the attacking host at the firewall."
        step["commands"] = [{"type": "bash",
                             "command": "iptables -I INPUT -s 192.168.0.49 -j DROP"}]
    good["name"] = "Nikto scan response"
    good["description"] = "Respond to a Nikto web vulnerability scan."

    bad = {"type": "playbook", "spec_version": "cacao-1.1", "id": "pb-123",
           "name": "x", "workflow_start": "step--missing",
           "workflow": {"a": {"type": "single", "name": "n",
                              "description": "<fill: what to do>",
                              "commands": [{"type": "bash", "command": "if then fi ("}],
                              "on_completion": "nope"}}}

    for label, pb in (("well-formed", good), ("broken", bad)):
        s = score_playbook(pb, alert_text(alerts[0]))
        print(f"  {label:12s} spec={s['spec_score']:3d} passed={str(s['spec_passed']):5s} "
              f"dag={str(s['is_dag']):5s} end_reach={str(s['end_reachable']):5s} "
              f"missing={s['missing_fields']} unfilled={s['n_unfilled']} "
              # exec_rate is None when a playbook has no locally checkable command
              f"exec={'n/a' if s['exec_rate'] is None else format(s['exec_rate'], '.2f')} "
              f"ioc_cmd={s['ioc_in_commands']} "
              f"halluc_ip={s['n_hallucinated_ip']}")
        if s["issue_desc"]:
            print(f"               issues: {s['issue_desc'][:3]}")
    print("\nDry run complete — no API calls made.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate LLMs on CACAO 2.0 playbook generation")
    ap.add_argument("--models", default="",
                    help="comma-separated subset of model names (default: all), "
                         "matching scripts/evaluate_llm_attribution.py")
    ap.add_argument("--mode", default="schema",
                    help=f"one of {', '.join(MODES)}, or 'all' (default: schema)")
    ap.add_argument("--oracle", action="store_true",
                    help="add the ground-truth technique to the prompt (upper bound: "
                         "generation quality with attribution error removed)")
    ap.add_argument("--repeats", type=int, default=1,
                    help="samples per cell; use >=3 for Ollama models, whose output "
                         "varies between identical runs even at temperature 0")
    ap.add_argument("--limit", type=int, default=0, help="use first N alerts")
    ap.add_argument("--sample", type=int, default=0,
                    help="stratified sample of N alerts across sensors (mmt/snort/suricata)")
    ap.add_argument("--alert-id", default="",
                    help="run only alerts whose id contains this substring")
    ap.add_argument("--score-only", action="store_true", help="re-score from cache, no calls")
    ap.add_argument("--retry-truncated", action="store_true",
                    help="re-call any cached response that hit the output cap "
                         "(finish=='length'). Needed after raising MAX_TOKENS: the cache "
                         "key does not include the output budget, so a truncated "
                         "response would otherwise be served forever.")
    ap.add_argument("--dry-run", action="store_true",
                    help="render prompts and self-test the scorer; no API calls")
    ap.add_argument("--verbose", action="store_true",
                    help="also print the full diagnostic table (all sub-metrics)")
    ap.add_argument("--no-bash-check", action="store_true",
                    help="skip `bash -n` syntax checking (it never executes commands)")
    ap.add_argument("--testset", default=TESTSET)
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()

    modes = list(MODES) if args.mode == "all" else [m.strip() for m in args.mode.split(",")]
    for m in modes:
        if m not in MODES:
            ap.error(f"unknown mode {m!r}; choose from {', '.join(MODES)} or 'all'")

    alerts = load_alerts(args.testset, args.limit, args.sample)
    if args.alert_id:
        alerts = [a for a in alerts if args.alert_id in a["id"]]
        if not alerts:
            ap.error(f"no alert id contains {args.alert_id!r}")
    if args.dry_run:
        dry_run(alerts, modes)
        return

    selected = MODELS if (not args.models or args.models == "all") else \
        [m for m in MODELS if m["name"] in {s.strip() for s in args.models.split(",")}]
    if not selected:
        ap.error(f"no model matched {args.models!r}; known: {[m['name'] for m in MODELS]}")

    os.makedirs(args.out, exist_ok=True)
    cache_path = os.path.join(args.out, "raw_cache.jsonl")
    cache      = load_cache(cache_path)

    print(f"models={[m['name'] for m in selected]}")
    print(f"alerts={len(alerts)}  modes={modes}  oracle={args.oracle}  "
          f"repeats={args.repeats}  score_only={args.score_only}")
    print(f"cells={len(selected) * len(modes) * len(alerts) * args.repeats}  "
          f"cached={len(cache)}")

    rows: List[Dict] = []
    cache_fp = open(cache_path, "a")
    for spec in selected:
        for mode in modes:
            for a in alerts:
                aid  = a["id"]
                gt   = a["ground_truth"]
                text = alert_text(a)
                tech = gt["technique_ids"][0] if (args.oracle and gt["technique_ids"]) else None
                for rep in range(args.repeats):
                    prompt = build_prompt(text, mode, technique=tech,
                                          seed=f"{aid}|{rep}")
                    key = cache_key(spec["name"], mode, aid, prompt, rep, spec)
                    rec = cache.get(key)
                    if (rec is not None and args.retry_truncated
                            and rec.get("finish") == "length" and not args.score_only):
                        rec = None
                    if rec is None and not args.score_only:
                        try:
                            r = call_spec(spec, prompt)
                            rec = {"key": key, "raw": r.text, "usage": r.usage,
                                   "latency": r.latency, "finish": r.finish,
                                   "reasoning": r.reasoning, "error": None}
                        except Exception as exc:
                            rec = {"key": key, "raw": "", "usage": {"in": 0, "out": 0},
                                   "latency": 0.0, "finish": None, "reasoning": "",
                                   "error": f"{type(exc).__name__}: {exc}"}
                        if rec["error"] is None:
                            cache[key] = rec
                            cache_fp.write(json.dumps(rec) + "\n"); cache_fp.flush()
                    if rec is None:
                        continue

                    pred = parse_playbook(rec["raw"], rec.get("reasoning") or "")
                    if pred["parse_ok"]:
                        sc = score_playbook(pred["playbook"], text,
                                            check_bash=not args.no_bash_check)
                        # declared-technique match: a plain field comparison against the
                        # benchmark label, no attribution model involved
                        sc.update(technique_match(pred["playbook"], gt))
                    else:
                        sc = empty_score("no parseable playbook in response")
                    in_c, out_c = spec["price"]
                    rows.append({
                        "model": spec["name"], "mode": mode, "alert_id": aid, "rep": rep,
                        "oracle": bool(tech), "error": rec["error"],
                        "json_valid": pred["json_valid"], "parse_ok": pred["parse_ok"],
                        "from_reasoning": pred["from_reasoning"],
                        "finish": rec.get("finish"),
                        "latency": rec["latency"],
                        "cost": (rec["usage"]["in"] * in_c + rec["usage"]["out"] * out_c) / 1e6,
                        "in_tok": rec["usage"]["in"], "out_tok": rec["usage"]["out"],
                        "playbook": pred["playbook"] if pred["parse_ok"] else None,
                        **sc,
                    })
    cache_fp.close()

    # Merge on (model, mode, alert_id, rep) instead of overwriting: hosted models run
    # here and local models on the GPU box, so a plain rewrite loses whichever ran first.
    detail = os.path.join(args.out, "results_detail.jsonl")
    merged: Dict[tuple, Dict] = {}
    if os.path.exists(detail):
        for line in open(detail):
            line = line.strip()
            if line:
                old = json.loads(line)
                merged[(old["model"], old["mode"], old["alert_id"], old.get("rep", 0))] = old
    for r in rows:
        merged[(r["model"], r["mode"], r["alert_id"], r.get("rep", 0))] = r
    with open(detail, "w") as f:
        for r in merged.values():
            f.write(json.dumps(r, default=str) + "\n")

    if not rows:
        print("\nno results — with --score-only this means nothing is cached yet")
        return

    print("\n" + "=" * 108)
    print(f"{'model':20s} {'mode':9s} {'n':>4s} {'parse%':>7s} {'schema%':>8s} "
          f"{'flow%':>6s} {'exec%':>6s} {'IOC%':>6s} {'T@1':>6s} {'destr%':>7s} "
          f"{'lat_s':>7s} {'cost$':>8s} {'err':>4s}")
    print("-" * 126)
    agg = collections.defaultdict(list)
    for r in rows:
        agg[(r["model"], r["mode"])].append(r)
    for (m, mode), rs in sorted(agg.items()):
        pb = [r for r in rs if not r["error"] and r["parse_ok"]]
        def pct(field): return 100.0 * sum(1 for r in pb if r[field]) / len(pb) if pb else 0.0
        ok = [r for r in rs if not r["error"]]
        n_err = sum(1 for r in rs if r["error"])
        parse_pct = 100.0 * len(pb) / len(ok) if ok else 0.0
        if not pb:
            print(f"{m:20s} {mode:9s} {len(rs):4d} " +
                  " ".join("--".rjust(w) for w in (7, 8, 6, 6, 6, 6, 7, 7, 8)) +
                  f" {n_err:4d}")
            continue
        print(f"{m:20s} {mode:9s} {len(rs):4d} "
              f"{parse_pct:7.1f} {pct('schema_valid'):8.1f} {pct('flow_ok'):6.1f} "
              f"{100 * mean(r['exec_rate'] for r in pb):6.1f} "
              f"{100 * mean(r['ioc_in_commands'] for r in pb):6.1f} "
              f"{pct('tech_parent_ok'):6.1f} "
              f"{100 * mean(r['destructive_rate'] for r in pb):7.1f} "
              f"{mean(r['latency'] for r in ok):7.2f} "
              f"{sum(r['cost'] for r in rs):8.2f} "
              f"{n_err:4d}")
    print("=" * 126)
    print("n / err = alerts attempted / calls that failed outright (timeout, API error).\n"
          "          err rows are excluded from every other column's denominator\n"
          "cost$   = TOTAL USD for the whole run of n alerts, not per alert. Cached\n"
          "          responses cost nothing to re-score, so this is the price of the\n"
          "          original generation. Zero for locally served open-weight models\n"
          "parse%  = returned responses yielding a usable playbook object\n"
          "schema% = validates clean against the official OASIS CACAO 2.0 schemas\n"
          "flow%   = sound graph: DAG, end reachable, no orphan or dangling steps\n"
          "exec%   = checkable commands valid for their command type and placeholder-free\n"
          "T@1     = declared ATT&CK technique matches the benchmark label (parent level)\n"
          "IOC%    = alert indicators used inside a command. INFORMATIONAL: a correct\n"
          "          playbook need not use every indicator, so do not rank on this column\n"
          "destr%  = commands tripping the safety policy (lower is better)")

    if not args.verbose:
        print("\n(--verbose for the full diagnostic table: CACAO, decl%, unval, "
              "steps, cmds)")

    if args.verbose:
        print("\n" + "=" * 150)
        hdr = (f"{'model':20s} {'mode':9s} {'n':>4s} {'parse%':>7s} {'CACAO':>6s} "
               f"{'schema%':>8s} {'flow%':>6s} {'exec%':>6s} {'unval':>6s} {'IOC%':>6s} {'T@1':>6s} "
               f"{'decl%':>6s} {'destr%':>7s} {'steps':>6s} {'cmds':>5s} {'lat_s':>7s} "
               f"{'cost$':>8s} {'err':>4s}")
        print(hdr); print("-" * 150)
        agg = collections.defaultdict(list)
        for r in rows:
            agg[(r["model"], r["mode"])].append(r)

        for (m, mode), rs in sorted(agg.items()):
            ok = [r for r in rs if not r["error"]]
            pb = [r for r in ok if r["parse_ok"]]
            def pct(field, src): return 100.0 * sum(1 for r in src if r[field]) / len(src) if src else 0.0
            if not ok:
                reason = next((r["error"] for r in rs if r["error"]), "unknown")
                print(f"{m:20s} {mode:9s} {len(rs):4d} " + " ".join(["--".rjust(w) for w in
                      (7,6,8,6,6,6,6,6,6,7,6,5,7,8)]) + f" {len(rs):4d}   ALL CALLS FAILED")
                continue
            print(f"{m:20s} {mode:9s} {len(rs):4d} "
                  f"{pct('parse_ok', ok):7.1f} "
                  f"{mean(r['conformance'] for r in pb):6.1f} "
                  f"{pct('schema_valid', pb):8.1f} "
                  f"{pct('flow_ok', pb):6.1f} "
                  f"{100 * mean(r['exec_rate'] for r in pb):6.1f} "
                  f"{mean(r['n_unvalidated_cmds'] for r in pb):6.1f} "
                  f"{100 * mean(r['ioc_in_commands'] for r in pb):6.1f} "
                  f"{pct('tech_parent_ok', pb):6.1f} "
                  f"{pct('tech_declared', pb):6.1f} "
                  f"{100 * mean(r['destructive_rate'] for r in pb):7.1f} "
                  f"{mean(r['n_steps'] for r in pb):6.1f} "
                  f"{mean(r['n_commands'] for r in pb):5.1f} "
                  f"{mean(r['latency'] for r in ok):7.2f} "
                  f"{sum(r['cost'] for r in rs):8.2f} "
                  f"{sum(1 for r in rs if r['error']):4d}")
        print("=" * 150)
        print("CACAO   = our conformance checker, mean % of 15 spec check CATEGORIES passed\n"
              "schema% = share validating clean against the OFFICIAL OASIS CACAO 2.0 JSON\n"
              "          schemas (data/cacao-schemas/) - the only conformance signal not\n"
              "          produced by code in this repo. Stricter than CACAO; report both,\n"
              "          since JSON Schema cannot express graph reachability\n"
              "flow%  = share with a sound graph: DAG and end reachable and no orphan or "
              "dangling refs\n"
              "exec%  = share of CHECKABLE commands that validate for their command type and "
              "carry no placeholder;\n"
              "         unval = mean commands per playbook with no local validator "
              "(sigma/yara/manual/...), excluded from exec%\n"
              "IOC%   = alert indicators appearing inside a command. INFORMATIONAL ONLY - a "
              "correct playbook need not\n"
              "         use every indicator, so do not rank models on this column\n"
              "T@1    = declared ATT&CK technique (external_references, source mitre-attack) "
              "matches the benchmark\n"
              "         label at parent level; decl% = share that declared one at all\n"
              "destr% = share of commands tripping the safety policy (see _POLICY in "
              "path_d_metrics.py)\n"
              "cost$  = TOTAL USD for the whole run of n alerts, not per alert")

    # warnings that invalidate a cell rather than describing a model
    for (m, mode), rs in sorted(agg.items()):
        cut  = [r for r in rs if r.get("finish") == "length"]
        salv = [r for r in rs if r.get("from_reasoning")]
        nopb = [r for r in rs if not r["error"] and not r["parse_ok"]]
        bits = []
        if cut:  bits.append(f"{len(cut)}/{len(rs)} hit the output-token cap")
        if salv: bits.append(f"{len(salv)} salvaged from the thinking channel")
        if nopb: bits.append(f"{len(nopb)} returned no parseable playbook")
        if bits:
            print(f"WARNING {m} [{mode}]: " + "; ".join(bits) +
                  " -> raise this model's max_tokens in MODELS and re-run")

    top = [f for f in ("missing_names",) ]
    missing = collections.Counter()
    for r in rows:
        for f in (r.get("missing_names") or []):
            missing[f] += 1
    if missing:
        print(f"\nmost-missed required fields: {missing.most_common(6)}")

    errs = collections.Counter(r["error"] for r in rows if r["error"])
    if errs:
        print("\nCALL FAILURES (not cached, so these cells will retry on the next run):")
        for msg, n in errs.most_common(5):
            print(f"  {n:4d}x  {msg[:150]}")

    print(f"\nper-instance detail: {detail}\nraw cache: {cache_path}")
    print("Next: score quality with  python3 scripts/judge_path_d.py")


if __name__ == "__main__":
    main()

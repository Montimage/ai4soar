#!/usr/bin/env python3
"""
Standalone LLM MITRE-attribution evaluator for AI4SOAR (Phase 1 — Step 1: attribution).

What it does
------------
For each alert (text), asks each LLM to pick the SINGLE most likely MITRE ATT&CK
Enterprise technique from ONE shared vocabulary (ATT&CK v19.1), then scores the
prediction against the ground-truth labels — at parent level (primary) and exact
sub-technique level (secondary).

Inputs (produced earlier in the pipeline)
-----------------------------------------
  data/attack_enterprise_all.json        697 techniques {id: {name, tactics}}  (v19.1)
  data/attack_enterprise_parents.json    222 parent techniques {id: name}      (v19.1)

Providers
---------
  openai     : needs OPENAI_API_KEY
  anthropic  : needs ANTHROPIC_API_KEY
  ollama     : local, OpenAI-compatible at OLLAMA_BASE_URL (default localhost:11434)

Examples
--------
  # smoke test: 20 alerts, only the models you have, stripped condition
  python3 scripts/evaluate_llm_attribution.py --sample 20 \
      --models gpt-4o-mini,llama3.1:8b --condition stripped

  # full run, all default models, both conditions
  python3 scripts/evaluate_llm_attribution.py --condition both

  # re-score from cache without re-calling any model
  python3 scripts/evaluate_llm_attribution.py --score-only

  # measure the exact prompt production Path B sends (adds the "confidence" key)
  python3 scripts/evaluate_llm_attribution.py --condition both --ask-confidence
"""

import argparse
import collections
import hashlib
import json
import os
import sys
from typing import Dict, List, Optional

# Load API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) from the project .env,
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTSET     = os.path.join(ROOT, "datasets", "eval", "path_b_test_clean.jsonl")
OUT_DIR     = os.path.join(ROOT, "output", "llm_eval")

# Import the production attribution code so the benchmark measures what actually runs.
sys.path.insert(0, ROOT)
from utils.llm.attribution import (
    build_prompt, load_vocab, parse_prediction, vocab_string,
)
from utils.llm.client import call_model

MAX_TOKENS   = 300
DEFAULT_NUM_CTX = 16384
THINK_TOKENS = 16384
THINK_NUM_CTX = 32768

MODELS: List[Dict] = [
    {"name": "gpt-4o-mini",           "provider": "openai",    "model": "gpt-4o-mini",           "price": (0.15, 0.60)},
    {"name": "gpt-4o",                "provider": "openai",    "model": "gpt-4o",                "price": (2.50, 10.0)},
    {"name": "gpt-4.1",               "provider": "openai",    "model": "gpt-4.1",               "price": (2.00, 8.00)},
    {"name": "gpt-5-mini",            "provider": "openai",    "model": "gpt-5-mini",            "price": (0.25, 2.00)},
    {"name": "gpt-5",                 "provider": "openai",    "model": "gpt-5",                 "price": (1.25, 10.0), "reasoning_effort": "minimal"},
    {"name": "gpt-5-med",             "provider": "openai",    "model": "gpt-5",                 "price": (1.25, 10.0), "reasoning_effort": "medium"},
    {"name": "gpt-5-high",            "provider": "openai",    "model": "gpt-5",                 "price": (1.25, 10.0), "reasoning_effort": "high"},
    {"name": "claude-opus-4-8",       "provider": "anthropic", "model": "claude-opus-4-8",       "price": (1.00, 5.00)},
    {"name": "claude-haiku-4-5",      "provider": "anthropic", "model": "claude-haiku-4-5",      "price": (1.00, 5.00)},
    {"name": "claude-sonnet-5",       "provider": "anthropic", "model": "claude-sonnet-5",       "price": (3.00, 15.0)},
    {"name": "llama3.1:8b",           "provider": "ollama",    "model": "llama3.1:8b",           "price": (0, 0)},
    {"name": "llama3.2:3b",           "provider": "ollama",    "model": "llama3.2:3b",           "price": (0, 0)},
    {"name": "qwen3-coder-next:latest",  "provider": "ollama",    "model": "qwen3-coder-next:latest",  "price": (0, 0)},
    {"name": "qwen3.6:35b",           "provider": "ollama",    "model": "qwen3.6:35b",           "price": (0, 0), "max_tokens": THINK_TOKENS, "num_ctx": THINK_NUM_CTX},
    {"name": "mistral:7b",            "provider": "ollama",    "model": "mistral:7b",            "price": (0, 0)},
    {"name": "gemma4:12b",            "provider": "ollama",    "model": "gemma4:12b",            "price": (0, 0), "max_tokens": THINK_TOKENS, "num_ctx": THINK_NUM_CTX},
    {"name": "gemma3:12b",            "provider": "ollama",    "model": "gemma3:12b",            "price": (0, 0)},
    # gemma2:27b maxes out at an 8K context, thus run it with --vocab parents.
    {"name": "gemma2:27b",            "provider": "ollama",    "model": "gemma2:27b",            "price": (0, 0), "num_ctx": 8192},
    {"name": "phi3:14b",              "provider": "ollama",    "model": "phi3:14b",              "price": (0, 0)},
    {"name": "phi4:14b",              "provider": "ollama",    "model": "phi4:14b",              "price": (0, 0)},
    {"name": "gpt-oss:20b",           "provider": "ollama",    "model": "gpt-oss:20b",           "price": (0, 0), "max_tokens": THINK_TOKENS, "num_ctx": THINK_NUM_CTX},
]

# ---------------------------------------------------------------------------
# Alert -> text  (two conditions: description-stripped [primary], visible [reference])
# ---------------------------------------------------------------------------
def alert_to_text(alert: Dict, condition: str) -> str:
    src  = alert.get("_source", alert)
    rule = src.get("rule", {})
    data = src.get("data", {})
    parts: List[str] = []
    if condition == "visible":
        if rule.get("description"):
            parts.append(f"Rule: {rule['description']}")
        if rule.get("groups"):
            parts.append(f"Groups: {', '.join(rule.get('groups', []))}")
    raw = data.get("raw_text") or data.get("message") or src.get("full_log", "")
    if raw:
        parts.append(f"Log: {str(raw)[:600]}")
    for key in ("event_type", "srcip", "dstip", "src_process", "user"):
        if data.get(key):
            parts.append(f"{key}: {data[key]}")
    return "\n".join(parts) if parts else json.dumps(src, default=str)[:1000]


def call_spec(spec: Dict, prompt: str):
    resolved = {**spec,
                "max_tokens": spec.get("max_tokens", MAX_TOKENS),
                "num_ctx":    spec.get("num_ctx", DEFAULT_NUM_CTX)}
    return call_model(resolved, prompt)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score(pred: Dict, gt: Dict, tactics: Dict[str, List[str]], valid_ids: set) -> Dict:
    ranked = pred.get("ranked") or []
    top    = ranked[0] if ranked else None
    parent = top.split(".")[0] if top else None
    parents_ranked = [t.split(".")[0] for t in ranked]
    gt_full    = set(gt["technique_ids"])
    gt_parents = set(gt["technique_parents"])
    gt_tactics = set(gt.get("tactic", []))
    pred_tactics = set(tactics.get(parent, [])) if parent else set()
    oov = [t for t in ranked if t not in valid_ids]

    def hit_parent(k: int) -> bool:
        return any(p in gt_parents for p in parents_ranked[:k])

    def hit_exact(k: int) -> bool:
        return any(t in gt_full for t in ranked[:k])

    return {
        "pred_id":       top,
        "pred_parent":   parent,
        "in_vocab":      bool(top and top in valid_ids),
        "n_ranked":      len(ranked),
        "n_oov":         len(oov),
        "oov_ids":       oov,
        "any_oov":       bool(oov),
        "parent_hit1":   hit_parent(1),
        "parent_hit3":   hit_parent(3),
        "parent_hit5":   hit_parent(5),
        "exact_hit1":    hit_exact(1),
        "exact_hit3":    hit_exact(3),
        "exact_hit5":    hit_exact(5),
        "tactic_correct": bool(pred_tactics & gt_tactics),
    }


# ---------------------------------------------------------------------------
# Cache (keyed by model|condition|alert_id) so re-runs / re-scoring are free
# ---------------------------------------------------------------------------
def cache_key(model_name: str, condition: str, alert_id: str, prompt: str,
              spec: Optional[Dict] = None) -> str:
    h = hashlib.sha1(prompt.encode()).hexdigest()[:8]
    base = f"{model_name}|{condition}|{alert_id}|{h}"
    if spec and spec["provider"] == "ollama":
        base += f"|ctx{spec.get('num_ctx', DEFAULT_NUM_CTX)}|out{spec.get('max_tokens', MAX_TOKENS)}"
    return base

def load_cache(cache_path: str) -> Dict[str, Dict]:
    c = {}
    if os.path.exists(cache_path):
        for line in open(cache_path):
            line = line.strip()
            if line:
                r = json.loads(line)
                c[r["key"]] = r
    return c


# ---------------------------------------------------------------------------
# Data loading + stratified sampling
# ---------------------------------------------------------------------------
def load_alerts(path: str, limit: int, sample: int) -> List[Dict]:
    rows = [json.loads(l) for l in open(path) if l.strip()]
    if sample:
        by = collections.defaultdict(list)
        for r in rows:
            key = (r["ground_truth"].get("tactic") or ["?"])[0]
            by[key].append(r)
        picked, groups = [], list(by.values())
        i = 0
        while len(picked) < min(sample, len(rows)):
            g = groups[i % len(groups)]
            if g:
                picked.append(g.pop())
            i += 1
        rows = picked
    if limit:
        rows = rows[:limit]
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Evaluate LLMs on MITRE attribution (ATT&CK v19.1)")
    ap.add_argument("--models", default="", help="comma-separated subset of model names (default: all)")
    ap.add_argument("--condition", choices=["stripped", "visible", "both"], default="stripped")
    ap.add_argument("--vocab", choices=["all", "parents"], default="all",
                    help="candidate list shown in the prompt (scoring always uses full v19.1)")
    ap.add_argument("--limit", type=int, default=0, help="use first N alerts")
    ap.add_argument("--sample", type=int, default=0, help="stratified sample of N alerts (by tactic)")
    ap.add_argument("--score-only", action="store_true", help="re-score from cache, no model calls")
    ap.add_argument("--ask-confidence", action="store_true",
                    help="request the extra \"confidence\" key that production Path B gates "
                         "on. Changes the prompt, so it uses a separate set of cache keys.")
    ap.add_argument("--testset", default=TESTSET, help="path to a .jsonl test set")
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cache_path = os.path.join(args.out, "raw_cache.jsonl")
    names, tactics, valid_ids = load_vocab(args.vocab)
    vocab_str = vocab_string(args.vocab)
    alerts = load_alerts(args.testset, args.limit, args.sample)
    conditions = ["stripped", "visible"] if args.condition == "both" else [args.condition]
    selected = [m for m in MODELS if (not args.models or m["name"] in args.models.split(","))]
    cache = load_cache(cache_path)

    print(f"models={[m['name'] for m in selected]}")
    print(f"alerts={len(alerts)}  conditions={conditions}  vocab={args.vocab} ({len(names)} shown)  "
          f"score_only={args.score_only}")

    approx_prompt_tok = int(
        len(build_prompt(vocab_str, "x" * 700, ask_confidence=args.ask_confidence)) / 2.5
    )
    print(f"prompt ~{approx_prompt_tok} tokens (vocab={args.vocab}, "
          f"ask_confidence={args.ask_confidence})")
    for spec in selected:
        if spec["provider"] != "ollama":
            continue
        ctx = spec.get("num_ctx", DEFAULT_NUM_CTX)
        if approx_prompt_tok + spec.get("max_tokens", MAX_TOKENS) > ctx:
            print(f"WARNING {spec['name']}: prompt+output (~{approx_prompt_tok}+"
                  f"{spec.get('max_tokens', MAX_TOKENS)}) exceeds num_ctx={ctx} — the server will "
                  f"drop the front of the prompt (the vocab list). Use --vocab parents "
                  f"or raise num_ctx for this model.")

    rows_out = []
    cache_fp = open(cache_path, "a")
    for spec in selected:
        for cond in conditions:
            for a in alerts:
                gt = a["ground_truth"]
                aid = a.get("alert", {}).get("_id") or a.get("id") or "?"
                if "text" in a:                       # precomputed (real-alert set)
                    text = a["text"].get(cond, a["text"].get("stripped", ""))
                else:                                 # Wazuh/OTRF format
                    text = alert_to_text(a["alert"], cond)
                prompt = build_prompt(vocab_str, text, ask_confidence=args.ask_confidence)
                key = cache_key(spec["name"], cond, aid, prompt, spec)
                rec = cache.get(key)
                if rec is None and not args.score_only:
                    try:
                        r = call_spec(spec, prompt)
                        rec = {"key": key, "raw": r.text, "usage": r.usage,
                               "latency": r.latency, "error": None, "finish": r.finish,
                               "reasoning": r.reasoning}
                    except Exception as e:
                        rec = {"key": key, "raw": "", "usage": {"in": 0, "out": 0},
                               "latency": 0.0, "error": f"{type(e).__name__}: {e}",
                               "finish": None, "reasoning": ""}
                    if rec["error"] is None:
                        cache[key] = rec
                        cache_fp.write(json.dumps(rec) + "\n"); cache_fp.flush()
                if rec is None:      # score-only but not cached
                    continue
                pred = parse_prediction(rec["raw"], rec.get("reasoning") or "")
                sc = score(pred, gt, tactics, valid_ids)
                in_c, out_c = spec["price"]
                cost = (rec["usage"]["in"] * in_c + rec["usage"]["out"] * out_c) / 1e6
                rows_out.append({"model": spec["name"], "condition": cond, "alert_id": aid,
                                 "error": rec["error"], **pred, **sc,
                                 "finish": rec.get("finish"),
                                 "empty_answer": not (rec["raw"] or "").strip(),
                                 "latency": rec["latency"], "cost": cost,
                                 "in_tok": rec["usage"]["in"], "out_tok": rec["usage"]["out"]})
    cache_fp.close()

    # write per-instance results
    detail = os.path.join(args.out, "results_detail.jsonl")
    with open(detail, "w") as f:
        for r in rows_out:
            f.write(json.dumps(r) + "\n")

    # aggregate + print summary  (P@k = parent-level hit@k, E@k = exact-level hit@k,
    # OOV1% = top-1 not in vocab [rows], OOV% = predicted ids not in vocab [all ranks],
    # salv = rows whose answer channel was empty so the ranking came from the thinking
    # channel -- those rows score "mentioned while deliberating", NOT a ranked answer,
    # so any row with salv>0 is not a clean measurement: raise max_tokens and re-run)
    print("\n" + "=" * 146)
    hdr = f"{'model':22s} {'cond':9s} {'n':>5s} " \
          f"{'P@1':>6s} {'P@3':>6s} {'P@5':>6s} {'E@1':>6s} {'E@3':>6s} {'E@5':>6s} " \
          f"{'tactic%':>8s} {'OOV1%':>6s} {'OOV%':>6s} {'json%':>6s} {'err':>4s} " \
          f"{'salv':>5s} {'lat_s':>6s} {'cost$':>8s}"
    print(hdr); print("-" * 146)
    agg = collections.defaultdict(list)
    for r in rows_out:
        agg[(r["model"], r["condition"])].append(r)
    for (m, c), rs in sorted(agg.items()):
        n = len(rs); ok = [r for r in rs if not r["error"]]
        def pct(field): return 100.0 * sum(1 for r in ok if r[field]) / len(ok) if ok else 0.0
        errs = sum(1 for r in rs if r["error"])
        lat = sum(r["latency"] for r in ok) / len(ok) if ok else 0.0
        cost = sum(r["cost"] for r in rs)
        jsonp = 100.0 * sum(1 for r in ok if r["json_valid"]) / len(ok) if ok else 0.0
        # micro rate: share of ALL predicted ids (every rank, every row) outside the vocab
        n_ids = sum(r.get("n_ranked", 0) for r in ok)
        oovp = 100.0 * sum(r.get("n_oov", 0) for r in ok) / n_ids if n_ids else 0.0
        nsalv = sum(1 for r in ok if r.get("from_reasoning"))
        print(f"{m:22s} {c:9s} {n:5d} "
              f"{pct('parent_hit1'):6.1f} {pct('parent_hit3'):6.1f} {pct('parent_hit5'):6.1f} "
              f"{pct('exact_hit1'):6.1f} {pct('exact_hit3'):6.1f} {pct('exact_hit5'):6.1f} "
              f"{pct('tactic_correct'):8.1f} {100-pct('in_vocab'):6.1f} {oovp:6.1f} "
              f"{jsonp:6.1f} {errs:4d} {nsalv:5d} {lat:6.2f} {cost:8.4f}")
    print("=" * 146)

    for (m, c), rs in sorted(agg.items()):
        cut   = [r for r in rs if r.get("finish") == "length"]
        empty = [r for r in rs if r.get("empty_answer") and not r["error"]]
        salv  = [r for r in rs if r.get("from_reasoning")]
        if cut or empty or salv:
            bits = []
            if cut:   bits.append(f"{len(cut)}/{len(rs)} hit the output-token cap")
            if empty: bits.append(f"{len(empty)} returned an empty answer channel")
            if salv:  bits.append(f"{len(salv)} salvaged from the thinking channel")
            print(f"WARNING {m} [{c}]: " + "; ".join(bits) +
                  " -> raise this model's \"max_tokens\" in MODELS and re-run into a fresh --out")

    for (m, c), rs in sorted(agg.items()):
        ok = [r for r in rs if not r["error"]]
        n_ids = sum(r.get("n_ranked", 0) for r in ok)
        n_oov = sum(r.get("n_oov", 0) for r in ok)
        if n_ids and n_oov / n_ids >= 0.05:
            ex = sorted({t for r in ok for t in r.get("oov_ids", [])})[:6]
            print(f"WARNING {m} [{c}]: {n_oov}/{n_ids} predicted ids are outside the "
                  f"v19.1 vocab ({', '.join(ex)}...) -> the model is recalling ATT&CK from "
                  f"its weights, not selecting from the candidate list in the prompt")

    print(f"\nper-instance detail: {detail}\nraw cache: {cache_path}")


if __name__ == "__main__":
    main()

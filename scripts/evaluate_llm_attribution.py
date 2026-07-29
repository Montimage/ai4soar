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
  datasets/eval/path_b_test_clean.jsonl  3,034 alerts, GT reconciled to v19.1

Providers
---------
  openai     : needs OPENAI_API_KEY
  anthropic  : needs ANTHROPIC_API_KEY   (pip install anthropic)
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
"""

import argparse
import collections
import hashlib
import json
import os
import re
import sys
import time
from typing import Dict, List, Optional, Tuple

# Load API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) from the project .env,
# same as core/config.py, so the script works without exporting them manually.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional; env vars can still be exported manually

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VOCAB_ALL   = os.path.join(ROOT, "data", "attack_enterprise_all.json")
VOCAB_PAR   = os.path.join(ROOT, "data", "attack_enterprise_parents.json")
TESTSET     = os.path.join(ROOT, "datasets", "eval", "path_b_test_clean.jsonl")
OUT_DIR     = os.path.join(ROOT, "output", "llm_eval")
# raw_cache.jsonl now lives inside the run's --out dir (see main); each output
# folder keeps its own cache, so a custom --out is fully self-contained.

# ---------------------------------------------------------------------------
# Model registry — provider, model id, and $/1M tokens (input, output).
# Ollama models are free (0/0); cost column is ignored for them.
# Edit freely; --models selects a subset by name.
# ---------------------------------------------------------------------------
MAX_TOKENS   = 300
DEFAULT_NUM_CTX = 16384
THINK_TOKENS = 4096

MODELS: List[Dict] = [
    {"name": "gpt-4o-mini",           "provider": "openai",    "model": "gpt-4o-mini",           "price": (0.15, 0.60)},
    {"name": "gpt-4o",                "provider": "openai",    "model": "gpt-4o",                "price": (2.50, 10.0)},
    {"name": "gpt-4.1",               "provider": "openai",    "model": "gpt-4.1",               "price": (2.00, 8.00)},
    {"name": "gpt-5-mini",            "provider": "openai",    "model": "gpt-5-mini",            "price": (0.25, 2.00)},
    {"name": "gpt-5",                 "provider": "openai",    "model": "gpt-5",                 "price": (1.25, 10.0), "reasoning_effort": "minimal"},
    {"name": "gpt-5-med",             "provider": "openai",    "model": "gpt-5",                 "price": (1.25, 10.0), "reasoning_effort": "medium"},
    {"name": "gpt-5-high",            "provider": "openai",    "model": "gpt-5",                 "price": (1.25, 10.0), "reasoning_effort": "high"},
    {"name": "claude-haiku-4-5",      "provider": "anthropic", "model": "claude-haiku-4-5",      "price": (1.00, 5.00)},
    {"name": "claude-sonnet-5",       "provider": "anthropic", "model": "claude-sonnet-5",       "price": (3.00, 15.0)},
    {"name": "llama3.1:8b",           "provider": "ollama",    "model": "llama3.1:8b",           "price": (0, 0)},
    {"name": "llama3.2:3b",           "provider": "ollama",    "model": "llama3.2:3b",           "price": (0, 0)},
    {"name": "qwen3-coder-next:latest",  "provider": "ollama",    "model": "qwen3-coder-next:latest",  "price": (0, 0)},
    {"name": "qwen3.6:35b",           "provider": "ollama",    "model": "qwen3.6:35b",           "price": (0, 0), "max_tokens": THINK_TOKENS},
    {"name": "mistral:7b",            "provider": "ollama",    "model": "mistral:7b",            "price": (0, 0)},
    {"name": "gemma4:12b",            "provider": "ollama",    "model": "gemma4:12b",            "price": (0, 0), "max_tokens": THINK_TOKENS},
    {"name": "gemma3:12b",            "provider": "ollama",    "model": "gemma3:12b",            "price": (0, 0)},
    # gemma2:27b maxes out at an 8K context, thus run it with --vocab parents.
    {"name": "gemma2:27b",            "provider": "ollama",    "model": "gemma2:27b",            "price": (0, 0), "num_ctx": 8192},
    {"name": "phi3:14b",              "provider": "ollama",    "model": "phi3:14b",              "price": (0, 0)},
    {"name": "phi4:14b",              "provider": "ollama",    "model": "phi4:14b",              "price": (0, 0)},
    {"name": "gpt-oss:20b",           "provider": "ollama",    "model": "gpt-oss:20b",           "price": (0, 0), "max_tokens": THINK_TOKENS},
]

# ---------------------------------------------------------------------------
# Prompt template — edit here to iterate. {vocab} and {alert} are filled in.
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
{{"techniques": ["Txxxx", "Txxxx", "Txxxx", "Txxxx", "Txxxx"], "reasoning": "one short sentence"}}

Rules:
- Provide EXACTLY 5 technique IDs, ranked most likely first, with no duplicates.
- The "Txxxx" above are a FORMAT EXAMPLE ONLY — do not reuse them. Choose the real
  IDs from the list above based on what THIS alert actually shows.
- Every ID MUST be one of the IDs in the list above.
- If you are confident of a specific sub-technique (e.g. use the "id: name" line for
  it), use it; otherwise use the parent technique ID.
- Output the JSON and nothing else."""


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
def load_vocab(which: str) -> Tuple[Dict[str, str], Dict[str, List[str]], set]:
    """Return (id->name, id->tactics, set_of_all_valid_ids_for_scoring)."""
    allv = json.load(open(VOCAB_ALL))                    # {id: {name, tactics}}
    tactics = {k: v.get("tactics", []) for k, v in allv.items()}
    if which == "parents":
        names = json.load(open(VOCAB_PAR))               # {id: name}
    else:
        names = {k: v["name"] for k, v in allv.items()}
    valid_ids = set(allv.keys())                         # scoring always vs full v19.1
    return names, tactics, valid_ids


def vocab_string(names: Dict[str, str]) -> str:
    return "\n".join(f"{tid}: {names[tid]}" for tid in sorted(names))


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


# ---------------------------------------------------------------------------
# Provider calls -> (raw_text, usage{in,out}, latency_s, meta)
#
# meta carries the two things needed to tell "the model answered wrong" apart from
# "the harness never saw an answer": `finish` (finish_reason — "length" means the
# output budget ran out) and `reasoning` (thinking-model output, which Ollama and
# some OpenAI-compatible servers return in a separate field, leaving content empty).
# ---------------------------------------------------------------------------
def _is_reasoning(model: str) -> bool:
    """gpt-5*, o1/o3/o4* are reasoning models with a different chat-completions contract."""
    return model.startswith("gpt-5") or re.match(r"^o[134]", model) is not None

def _reasoning_text(msg) -> str:
    """Thinking output, wherever the server put it (field name varies by backend)."""
    for attr in ("reasoning_content", "reasoning", "thinking"):
        val = getattr(msg, attr, None)
        if isinstance(val, str) and val.strip():
            return val
    extra = getattr(msg, "model_extra", None) or {}
    for attr in ("reasoning_content", "reasoning", "thinking"):
        val = extra.get(attr)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def _openai_compat(spec: Dict, prompt: str, base_url: Optional[str], api_key: str) -> Tuple[str, Dict, float, Dict]:
    import openai
    client = openai.OpenAI(api_key=api_key, base_url=base_url) if base_url else openai.OpenAI(api_key=api_key)
    kwargs = dict(model=spec["model"],
                  messages=[{"role": "user", "content": prompt}])
    if _is_reasoning(spec["model"]):
        # reasoning models: no custom temperature; reasoning tokens share the output
        # budget, so give plenty of room and keep reasoning cheap.
        effort = spec.get("reasoning_effort", "minimal")
        # higher effort burns more reasoning tokens -> give the output budget more room
        kwargs["max_completion_tokens"] = {"minimal": 2000, "high": 12000}.get(effort, 6000)
        kwargs["reasoning_effort"] = effort
        kwargs["seed"] = 0
    else:
        kwargs["max_tokens"] = spec.get("max_tokens", MAX_TOKENS)
        kwargs["temperature"] = 0
        if spec["provider"] == "ollama":
            kwargs["extra_body"] = {"options": {
                "seed": 0, "num_ctx": spec.get("num_ctx", DEFAULT_NUM_CTX)}}
        else:
            kwargs["seed"] = 0
    t0 = time.time()
    resp = client.chat.completions.create(**kwargs)
    dt = time.time() - t0
    u = resp.usage
    usage = {"in": getattr(u, "prompt_tokens", 0) or 0, "out": getattr(u, "completion_tokens", 0) or 0}
    choice = resp.choices[0]
    meta = {"finish": choice.finish_reason, "reasoning": _reasoning_text(choice.message)}
    return choice.message.content or "", usage, dt, meta


def _anthropic(spec: Dict, prompt: str) -> Tuple[str, Dict, float, Dict]:
    import anthropic
    client = anthropic.Anthropic(api_key=_require_key("ANTHROPIC_API_KEY"))
    t0 = time.time()
    # NOTE: current Anthropic models reject temperature/top_p -> omit them.
    resp = client.messages.create(model=spec["model"],
                                  max_tokens=spec.get("max_tokens", MAX_TOKENS),
                                  messages=[{"role": "user", "content": prompt}])
    dt = time.time() - t0
    txt = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    think = "".join(getattr(b, "thinking", "") for b in resp.content
                    if getattr(b, "type", "") == "thinking")
    usage = {"in": resp.usage.input_tokens, "out": resp.usage.output_tokens}
    # stop_reason "max_tokens" is Anthropic's equivalent of finish_reason "length"
    meta = {"finish": "length" if resp.stop_reason == "max_tokens" else resp.stop_reason,
            "reasoning": think}
    return txt, usage, dt, meta


def _require_key(name: str) -> str:
    key = os.getenv(name)
    if not key:
        raise RuntimeError(f"{name} not set (add it to .env or export it) — cannot call this model")
    return key


def call_model(spec: Dict, prompt: str) -> Tuple[str, Dict, float, Dict]:
    p = spec["provider"]
    if p == "openai":
        return _openai_compat(spec, prompt, None, _require_key("OPENAI_API_KEY"))
    if p == "ollama":
        base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        return _openai_compat(spec, prompt, base, "ollama")
    if p == "anthropic":
        return _anthropic(spec, prompt)
    raise ValueError(f"unknown provider {p}")


# ---------------------------------------------------------------------------
# Parse model output
# ---------------------------------------------------------------------------
_TCODE = re.compile(r"T\d{4}(?:\.\d{3})?")
_THINK = re.compile(r"<(think|thinking|reasoning)>.*?(</\1>|\Z)", re.S)

def _strip_think(s: str) -> str:
    """Drop inline thinking blocks: their candidate IDs are not the model's answer."""
    return _THINK.sub("", s).strip()

def parse_prediction(raw: str, reasoning: str = "") -> Dict:
    """Return {ranked, technique_id, json_valid, parse_ok, from_reasoning}.

    `ranked` is the ordered list of predicted technique IDs (deduped, order kept);
    `technique_id` is the top-1 (kept for OOV/json/tactic single-pick metrics).
    `reasoning` is the separate thinking channel, used only as a last resort when the
    answer channel is empty (thinking model truncated before its final message);
    such rows are flagged `from_reasoning` and never counted as valid JSON.
    """
    out = {"ranked": [], "technique_id": None, "json_valid": False, "parse_ok": False,
           "from_reasoning": False}
    body = _strip_think(raw)
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
    """Key = model|condition|alert|prompt-hash, plus the runtime knobs that change the
    answer. Ollama gets a ctx/out suffix so rows produced under a different context
    window or output budget are not silently reused (entries cached before num_ctx was
    sent were computed on a truncated prompt and must not be mixed in). API providers
    keep the original key shape so existing paid runs stay valid."""
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
    ap.add_argument("--testset", default=TESTSET, help="path to a .jsonl test set")
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cache_path = os.path.join(args.out, "raw_cache.jsonl")
    names, tactics, valid_ids = load_vocab(args.vocab)
    vocab_str = vocab_string(names)
    alerts = load_alerts(args.testset, args.limit, args.sample)
    conditions = ["stripped", "visible"] if args.condition == "both" else [args.condition]
    selected = [m for m in MODELS if (not args.models or m["name"] in args.models.split(","))]
    cache = load_cache(cache_path)

    print(f"models={[m['name'] for m in selected]}")
    print(f"alerts={len(alerts)}  conditions={conditions}  vocab={args.vocab} ({len(names)} shown)  "
          f"score_only={args.score_only}")

    approx_prompt_tok = int(len(PROMPT_TEMPLATE.format(vocab=vocab_str, alert="x" * 700)) / 2.5)
    print(f"prompt ~{approx_prompt_tok} tokens (vocab={args.vocab})")
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
                prompt = PROMPT_TEMPLATE.format(vocab=vocab_str, alert=text)
                key = cache_key(spec["name"], cond, aid, prompt, spec)
                rec = cache.get(key)
                if rec is None and not args.score_only:
                    try:
                        raw, usage, dt, meta = call_model(spec, prompt)
                        rec = {"key": key, "raw": raw, "usage": usage, "latency": dt,
                               "error": None, "finish": meta.get("finish"),
                               "reasoning": meta.get("reasoning", "")}
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
    # OOV1% = top-1 not in vocab [rows], OOV% = predicted ids not in vocab [all ranks])
    print("\n" + "=" * 138)
    hdr = f"{'model':22s} {'cond':9s} {'n':>5s} " \
          f"{'P@1':>6s} {'P@3':>6s} {'P@5':>6s} {'E@1':>6s} {'E@3':>6s} {'E@5':>6s} " \
          f"{'tactic%':>8s} {'OOV1%':>6s} {'OOV%':>6s} {'json%':>6s} {'err':>4s} " \
          f"{'lat_s':>6s} {'cost$':>8s}"
    print(hdr); print("-" * 138)
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
        print(f"{m:22s} {c:9s} {n:5d} "
              f"{pct('parent_hit1'):6.1f} {pct('parent_hit3'):6.1f} {pct('parent_hit5'):6.1f} "
              f"{pct('exact_hit1'):6.1f} {pct('exact_hit3'):6.1f} {pct('exact_hit5'):6.1f} "
              f"{pct('tactic_correct'):8.1f} {100-pct('in_vocab'):6.1f} {oovp:6.1f} "
              f"{jsonp:6.1f} {errs:4d} {lat:6.2f} {cost:8.4f}")
    print("=" * 138)

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

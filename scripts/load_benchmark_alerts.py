#!/usr/bin/env python3
"""
Load the 37-alert SIEM benchmark (MMT / Suricata / Snort) into MongoDB so the web UI
can list it and hand individual alerts to the orchestrator.

Sources (both keyed on the same `id`):
  datasets/eval/alert_benchmark_raw.csv    — source_tool, signature, ground truth, raw alert
  datasets/eval/alert_benchmark_eval.jsonl — the exact `visible` / `stripped` prompt texts
                                             the Path B benchmark was measured on

Each row becomes one document in the `benchmark_alerts` collection, shaped like the
canonical envelope the enrichment pipeline and the alerts table already understand:

    {timestamp, rule:{description, level, groups}, data:{srcip, dstip, raw_text},
     agent:{name}, _adapter, _benchmark:{...}}

Two deliberate choices:

  * The MITRE ground truth lives under `_benchmark`, NEVER under `rule.mitre`.
    extract_mitre_ids() reads only `_source.rule.mitre`, so these alerts carry no
    technique tags, Path A cannot fire, and every alert routes to Stage 2 — which is
    the point: the benchmark exists to test LLM attribution, not tag lookup.

  * `data.raw_text` is the benchmark's own `visible` text verbatim, so what Path B
    reads in production is what the offline evaluator measured. `_benchmark.text`
    keeps both modes; the UI swaps them when the analyst picks "signature stripped".

Usage:
    python3 scripts/load_benchmark_alerts.py              # load (idempotent upsert)
    python3 scripts/load_benchmark_alerts.py --drop       # wipe the collection first
    python3 scripts/load_benchmark_alerts.py --dry-run    # print what would be loaded
"""

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import config  # noqa: E402

ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_CSV   = os.path.join(ROOT, "datasets", "eval", "alert_benchmark_raw.csv")
EVAL_JSON = os.path.join(ROOT, "datasets", "eval", "alert_benchmark_eval.jsonl")

# Severity → Wazuh-style level, so the existing severity badge renders sensibly.
# Suricata `alert.severity` and Snort `[Priority: N]` share the 1=worst convention.
_PRIORITY_LEVEL = {1: 12, 2: 9, 3: 6, 4: 4}
_MMT_LEVEL      = {"attack": 12, "anomaly": 7, "warning": 5, "info": 3}

csv.field_size_limit(10 * 1024 * 1024)


# ---------------------------------------------------------------------------
# Per-tool parsing of the raw alert — timestamp, endpoints, severity
# ---------------------------------------------------------------------------
def _parse_suricata(raw: str) -> Dict[str, Any]:
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    alert = obj.get("alert") or {}
    src, dst = obj.get("src_ip"), obj.get("dest_ip")
    sport, dport = obj.get("src_port"), obj.get("dest_port")
    return {
        "timestamp": obj.get("timestamp"),
        "srcip": f"{src}:{sport}" if src and sport else src,
        "dstip": f"{dst}:{dport}" if dst and dport else dst,
        "level": _PRIORITY_LEVEL.get(alert.get("severity"), 7),
        "category": alert.get("category"),
    }


_SNORT_RE = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"([\d.]+)(?::(\d+))?\s*->\s*([\d.]+)(?::(\d+))?"
)
_SNORT_PRIO = re.compile(r"\[Priority:\s*(\d+)\]")


def _parse_snort(raw: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    m = _SNORT_RE.search(raw)
    if m:
        ts, src, sport, dst, dport = m.groups()
        # Snort's unified2 text format carries no year — keep the literal stamp rather
        # than inventing one, and let the UI show it as the sensor wrote it.
        out["timestamp"] = ts
        out["srcip"] = f"{src}:{sport}" if sport else src
        out["dstip"] = f"{dst}:{dport}" if dport else dst
    p = _SNORT_PRIO.search(raw)
    out["level"] = _PRIORITY_LEVEL.get(int(p.group(1)), 7) if p else 7
    m2 = re.search(r"\[Classification:\s*([^\]]+)\]", raw)
    if m2:
        out["category"] = m2.group(1).strip()
    return out


def _parse_mmt(raw: str) -> Dict[str, Any]:
    """MMT rows are a CSV line: ...,<unix_ts>,<code>,"detected","attack","<desc>",{events}"""
    out: Dict[str, Any] = {}
    m = re.search(r",(1[0-9]{9}),", raw)          # 10-digit unix seconds
    if m:
        out["timestamp"] = datetime.fromtimestamp(
            int(m.group(1)), tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    for cat in ("attack", "anomaly", "warning", "info"):
        if f'"{cat}"' in raw or f",{cat}," in raw:
            out["level"] = _MMT_LEVEL[cat]
            out["category"] = cat
            break
    brace = raw.find("{")
    if brace != -1:
        try:
            events = json.loads(raw[brace:])
            for ev in events.values():
                for key, val in ev.get("attributes", []):
                    if key == "ip.src":
                        out.setdefault("srcip", val)
                    elif key == "ip.dst":
                        out.setdefault("dstip", val)
        except Exception:
            pass
    return out


_PARSERS = {"suricata": _parse_suricata, "snort": _parse_snort, "mmt": _parse_mmt}


# ---------------------------------------------------------------------------
# Row → document
# ---------------------------------------------------------------------------
def _split(field: str) -> List[str]:
    """Split a multi-value CSV cell. The benchmark uses ';' inside the tactic column
    (e.g. "collection;credential-access") and ',' elsewhere, so accept both."""
    return [p.strip() for p in re.split(r"[;,]", field or "") if p.strip()]


def build_document(row: Dict[str, str], texts: Dict[str, str]) -> Dict[str, Any]:
    tool   = row["source_tool"].lower()
    parsed = _PARSERS.get(tool, lambda _r: {})(row.get("raw_alert", "")) or {}

    visible  = texts.get("visible", "")
    stripped = texts.get("stripped", "")

    data: Dict[str, Any] = {"raw_text": visible or row.get("raw_alert", "")[:2000]}
    if parsed.get("srcip"):
        data["srcip"] = parsed["srcip"]
    if parsed.get("dstip"):
        data["dstip"] = parsed["dstip"]
    if parsed.get("category"):
        data["event_type"] = parsed["category"]

    groups = ["benchmark", tool]
    if parsed.get("category"):
        groups.append(str(parsed["category"]).lower().replace(" ", "_"))

    return {
        "_id":       row["id"],
        "timestamp": parsed.get("timestamp") or "",
        # No `mitre` key here — see the module docstring.
        "rule": {
            "description": row["signature"],
            "level":       parsed.get("level", 7),
            "groups":      groups,
        },
        "data":     data,
        "agent":    {"name": f"{tool}-sensor"},
        "_adapter": tool,
        "_benchmark": {
            "id":           row["id"],
            "source_tool":  tool,
            "signature":    row["signature"],
            "ground_truth": {
                "technique_ids":     _split(row.get("technique_ids")),
                "technique_names":   _split(row.get("technique_names")),
                "technique_parents": _split(row.get("technique_parents")),
                "parent_names":      _split(row.get("parent_names")),
                "tactic":            _split(row.get("tactic")),
            },
            "label_confidence": row.get("label_confidence", ""),
            "note":             row.get("note", ""),
            "raw_path":         row.get("raw_path", ""),
            # Both prompt modes the 37-alert benchmark was scored on.
            "text": {"visible": visible, "stripped": stripped},
        },
    }


def load_rows() -> List[Dict[str, Any]]:
    if not os.path.exists(RAW_CSV):
        raise SystemExit(f"missing {RAW_CSV}")

    texts: Dict[str, Dict[str, str]] = {}
    if os.path.exists(EVAL_JSON):
        with open(EVAL_JSON, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    texts[rec["id"]] = rec.get("text", {})
    else:
        print(f"  ! {EVAL_JSON} not found — falling back to raw_alert for prompt text")

    with open(RAW_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    missing = [r["id"] for r in rows if r["id"] not in texts]
    if missing:
        print(f"  ! {len(missing)} row(s) have no eval text: {missing[:3]}")

    return [build_document(r, texts.get(r["id"], {})) for r in rows]


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--drop", action="store_true", help="drop the collection first")
    ap.add_argument("--dry-run", action="store_true", help="print, do not write")
    args = ap.parse_args()

    docs = load_rows()
    by_tool: Dict[str, int] = {}
    for d in docs:
        by_tool[d["_adapter"]] = by_tool.get(d["_adapter"], 0) + 1

    print(f"\n  {len(docs)} benchmark alerts "
          f"({', '.join(f'{k}={v}' for k, v in sorted(by_tool.items()))})\n")

    for d in docs[:3] if args.dry_run else []:
        print(json.dumps(d, indent=2)[:900], "\n  ---")

    if args.dry_run:
        print("  dry run — nothing written")
        return 0

    from pymongo import MongoClient
    client = MongoClient(config.mongodb.host, config.mongodb.port,
                         serverSelectionTimeoutMS=5000)
    coll = client[config.mongodb.database][config.mongodb.benchmark_collection]

    if args.drop:
        coll.drop()
        print(f"  dropped {config.mongodb.benchmark_collection}")

    for d in docs:
        coll.replace_one({"_id": d["_id"]}, d, upsert=True)

    coll.create_index("_benchmark.source_tool")
    coll.create_index("rule.description")

    print(f"  → {coll.count_documents({})} documents in "
          f"{config.mongodb.database}.{config.mongodb.benchmark_collection}")
    for tool in sorted(by_tool):
        n = coll.count_documents({"_benchmark.source_tool": tool})
        print(f"      {tool:<10} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

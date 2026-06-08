"""
Direct CLI for the intelligent_orchestration component.

Usage (run from project root):
    python3 -m core.intelligent_orchestration
    python3 -m core.intelligent_orchestration --alert datasets/sample_alerts/wazuh_alert_t1021_002.json
    python3 -m core.intelligent_orchestration --alert datasets/sample_alerts/alert_path_b_ssh_bruteforce.json
    python3 -m core.intelligent_orchestration --alert datasets/sample_alerts/alert_path_c_powershell_tactic.json
    python3 -m core.intelligent_orchestration --alert datasets/sample_alerts/alert_path_d_novel_ot_threat.json
    python3 -m core.intelligent_orchestration --alert datasets/sample_alerts/wazuh_alert_t1021_002.json --k 3
    python3 -m core.intelligent_orchestration --json   # machine-readable output
    python3 -m core.intelligent_orchestration --no-save  # skip writing output file

Each run saves a JSON artifact to output/cacao/<timestamp>_<alert_stem>.json.

No dependencies beyond the installed requirements — no Flask, no server needed.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

# Allow running from project root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.intelligent_orchestration.enrichment.pipeline import EnrichmentPipeline
from core.intelligent_orchestration.orchestrator import PlaybookOrchestrator
from core.playbook_verification.verifier import PlaybookVerifier

_SAMPLES = {
    "A": "datasets/sample_alerts/wazuh_alert_t1021_002.json",
    "B": "datasets/sample_alerts/alert_path_b_ssh_bruteforce.json",
    "C": "datasets/sample_alerts/alert_path_c_powershell_tactic.json",
    "D": "datasets/sample_alerts/alert_path_d_novel_ot_threat.json",
}

_OUTPUT_DIR   = "output/cacao"
_TIER_COLOUR  = {"HIGH": "\033[92m", "MEDIUM": "\033[93m", "LOW": "\033[91m"}
_RESET        = "\033[0m"


def _verify_playbooks(playbooks: list) -> list:
    """Run structural CACAO verification on each generated playbook."""
    verifier = PlaybookVerifier()
    reports  = []
    for pb in playbooks:
        cacao = pb.get("cacao", {})
        if not cacao:
            continue
        try:
            report = verifier.verify(cacao, structural_only=True)
        except Exception as exc:
            report = {"overall_score": 0, "passed": False, "issues": [{"description": str(exc), "severity": "error"}]}
        reports.append({"playbook_id": pb.get("id"), "verification": report})
    return reports


def _save(alert_path: str, alert: dict, result_dict: dict, elapsed_ms: float, verif: list) -> str:
    """Save the orchestration result + verification report. Returns the output path."""
    os.makedirs(_OUTPUT_DIR, exist_ok=True)
    ts        = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem      = os.path.splitext(os.path.basename(alert_path))[0]
    out_path  = os.path.join(_OUTPUT_DIR, f"{ts}_{stem}.json")
    artifact  = {
        "generated_at":  ts,
        "alert_source":  alert_path,
        "alert_id":      alert.get("_id", stem),
        "elapsed_ms":    round(elapsed_ms, 1),
        "result":        result_dict,
        "verification":  verif,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2, default=str)
    return out_path


def _run(alert_path: str, k: int, as_json: bool, save: bool) -> None:
    if not os.path.exists(alert_path):
        print(f"Error: file not found — {alert_path}", file=sys.stderr)
        sys.exit(1)

    with open(alert_path) as f:
        alert = json.load(f)

    pipeline     = EnrichmentPipeline()
    orchestrator = PlaybookOrchestrator()

    enriched    = pipeline.enrich(alert)
    t0          = time.perf_counter()
    result      = orchestrator.orchestrate(enriched, k=k)
    elapsed     = time.perf_counter() - t0
    elapsed_ms  = elapsed * 1000
    result_dict = result.to_dict()

    # ── verify + persist ─────────────────────────────────────────────────
    verif    = _verify_playbooks(result.playbooks)
    out_path = None
    if save:
        out_path = _save(alert_path, alert, result_dict, elapsed_ms, verif)

    if as_json:
        print(json.dumps(result_dict, indent=2, default=str))
        if out_path:
            print(f"\n# Saved → {out_path}", file=sys.stderr)
        return

    tier   = result.confidence_tier
    colour = _TIER_COLOUR.get(tier, "")
    sep    = "─" * 60

    alert_techniques  = enriched.technique_ids or []
    result_techniques = result.technique_ids or []
    result_names      = result.technique_names or []

    print(f"\n{sep}")
    print(f"  Alert     : {alert_path}")
    print(f"  Format    : {enriched.source_format}")
    if alert_techniques:
        print(f"  Techniques: {alert_techniques}  (from alert)")
    print(sep)
    print(f"  Stage     : {'→'.join(result.paths_used)}")
    print(f"  Source    : {result.source}")
    print(f"  Confidence: {result.confidence:.3f}  tier={colour}{tier}{_RESET}")

    routing = (
        "auto-execute" if result.auto_executable else
        "needs approval" if result.requires_human_approval else
        "REVIEW required"
    )
    print(f"  Routing   : {routing}")

    if result.tactics:
        print(f"  Tactics   : {', '.join(result.tactics)}")

    if result_techniques:
        print(f"  Techniques ({len(result_techniques)} attributed):")
        for tid, tname in zip(result_techniques, result_names or result_techniques):
            print(f"    • {tid:<14} {tname}")
    else:
        print(f"  Techniques: (none attributed)")

    if result.llm_reasoning:
        print(f"  LLM note  : {result.llm_reasoning[:120]}")

    print(f"\n  Playbooks ({len(result.playbooks)})  ← parameterized CACAO:")
    for pb in result.playbooks:
        pb_id   = pb.get("id", "")
        pb_name = pb.get("cacao", {}).get("name") or pb.get("name", "")
        filled  = pb.get("parameters_filled", {})
        missing = pb.get("parameters_missing", [])
        cacao   = pb.get("cacao", {})

        print(f"\n  ┌ {pb_id}")
        print(f"  │ Name      : {pb_name}")
        if pb.get("techniques"):
            print(f"  │ Techniques: {', '.join(pb['techniques'])}")
        if filled:
            params_str = "  ".join(f"{k}={v}" for k, v in filled.items())
            print(f"  │ IOCs      : {params_str}")
        if missing:
            print(f"  │ Missing   : {', '.join(missing)}  ← not found in alert")
        steps = {k: v for k, v in cacao.get("workflow", {}).items()
                 if v.get("type") != "end"}
        if steps:
            print(f"  │ Steps:")
            for step in steps.values():
                cmds = step.get("commands", [])
                cmd  = cmds[0]["command"][:80] if cmds else "(no command)"
                print(f"  │   [{step.get('name', '?')}]")
                print(f"  │     {cmd}")

    if result.cacao_playbook:
        cacao = result.cacao_playbook
        steps = {k: v for k, v in cacao.get("workflow", {}).items()
                 if v.get("type") != "end"}
        print(f"\n  CACAO 2.0 (Path D) — {cacao.get('name')}  [id: {cacao.get('id')}]")
        for step in steps.values():
            cmds = step.get("commands", [])
            cmd  = cmds[0]["command"][:72] if cmds else "(no command)"
            print(f"    [{step.get('name', '?')}] {cmd}")

    if verif:
        print(f"\n  Verification:")
        for v in verif:
            score  = v["verification"]["overall_score"]
            passed = v["verification"]["passed"]
            mark   = "\033[92m✓\033[0m" if passed else "\033[91m✗\033[0m"
            print(f"    {mark} {v['playbook_id']}  score={score}/100")
            for issue in v["verification"].get("issues", []):
                sev = issue.get("severity", "warning")
                print(f"      [{sev}] {issue['description']}")

    print(f"\n  Elapsed   : {elapsed_ms:.1f} ms")
    if out_path:
        print(f"  Saved     : {out_path}")
    print(sep)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python3 -m core.intelligent_orchestration",
        description="Run the PlaybookOrchestrator on a single alert.",
    )
    parser.add_argument(
        "--alert",
        default=_SAMPLES["A"],
        help="Path to alert JSON file (default: wazuh_alert_t1021_002.json)",
    )
    parser.add_argument("--k",       type=int, default=5,    help="Max playbooks (default 5)")
    parser.add_argument("--json",    action="store_true",    help="Output raw JSON")
    parser.add_argument("--no-save", action="store_true",    help="Skip writing output file")
    args = parser.parse_args()

    _run(args.alert, k=args.k, as_json=args.json, save=not args.no_save)


if __name__ == "__main__":
    main()

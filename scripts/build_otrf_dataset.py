#!/usr/bin/env python3
"""
Build a labeled training dataset from OTRF Security-Datasets.

For each scenario (YAML metadata file):
  1. Reads attack_mappings → tactic TA-codes + technique IDs
  2. Finds the local data file (ZIP or JSON) via URL→path conversion
  3. Parses events, normalizes to NormalizedAlert
  4. Assigns tactic label (most generalizable) + technique_ids (metadata)
  5. Writes JSONL record to the output file

Label strategy: TACTIC (14 classes) rather than individual technique ID.
  - More training samples per class → better generalization
  - A model trained to recognize "credential-access" behavior generalizes
    to new sub-techniques it has never seen (e.g., T1110.004 if added later)
  - At inference: predicted_tactic → STIX KB → all mitigations for that tactic

Output: datasets/otrf_normalized.jsonl
  Each line is a JSON object with NormalizedAlert fields + label metadata.

Run from project root:
    python3 scripts/build_otrf_dataset.py [--otrf-path ../Security-Datasets]
    python3 scripts/build_otrf_dataset.py --otrf-path ../Security-Datasets --max-events 300
"""

import argparse
import glob
import json
import logging
import os
import random
import sys
import zipfile
from dataclasses import asdict
from typing import Dict, Iterator, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml

from core.intelligent_orchestration.normalizer import auto_normalize, NormalizedAlert
from core.intelligent_orchestration.playbook_registry import ta_code_to_name

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_OTRF = os.environ.get("OTRF_PATH", "../Security-Datasets")
DEFAULT_OUTPUT = "datasets/otrf_normalized.jsonl"
DEFAULT_MAX_EVENTS = 200
RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# YAML metadata parsing
# ---------------------------------------------------------------------------

def iter_metadata(base: str) -> Iterator[Dict]:
    """Yield parsed YAML dicts from atomic/_metadata/ and compound/_metadata/."""
    for subdir in ("datasets/atomic/_metadata", "datasets/compound/_metadata"):
        pattern = os.path.join(base, subdir, "*.yaml")
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    meta = yaml.safe_load(f)
                if isinstance(meta, dict) and meta.get("attack_mappings") and meta.get("files"):
                    meta["_yaml_path"] = path
                    yield meta
            except Exception as e:
                logger.debug(f"Skipped {path}: {e}")


def get_tactic_labels(attack_mappings: List[Dict]) -> List[str]:
    """
    Return ALL unique tactic names for a scenario (multi-label).
    Preserves priority order so the first entry is the primary label.
    """
    PRIORITY = [
        "credential-access", "lateral-movement", "privilege-escalation",
        "execution", "persistence", "initial-access", "defense-evasion",
        "discovery", "collection", "exfiltration", "command-and-control",
        "impact", "reconnaissance", "resource-development",
    ]
    found: set = set()
    for m in attack_mappings:
        for ta in m.get("tactics", []):
            name = ta_code_to_name(str(ta))
            if name != "unknown":
                found.add(name)
    # Return in priority order so index-0 is always the primary tactic
    ordered = [p for p in PRIORITY if p in found]
    return ordered if ordered else []


def get_tactic_label(attack_mappings: List[Dict]) -> str:
    """Primary tactic label (backward compat — first in priority order)."""
    labels = get_tactic_labels(attack_mappings)
    return labels[0] if labels else "unknown"


def get_technique_ids(attack_mappings: List[Dict]) -> List[str]:
    """Return full technique IDs like ['T1110.001', 'T1021.004']."""
    ids = []
    for m in attack_mappings:
        tech = str(m.get("technique", "")).strip()
        sub = str(m.get("sub-technique", "") or "").strip()
        if tech:
            ids.append(f"{tech}.{sub}" if sub else tech)
    return ids


# ---------------------------------------------------------------------------
# File location
# ---------------------------------------------------------------------------

_GITHUB_PREFIX = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
)


def url_to_local(url: str, base: str) -> Optional[str]:
    """Convert a GitHub raw URL to the corresponding local file path."""
    if url.startswith(_GITHUB_PREFIX):
        rel = url[len(_GITHUB_PREFIX):]
        return os.path.join(base, rel)
    if not url.startswith("http"):
        return os.path.join(base, url)
    return None


# ---------------------------------------------------------------------------
# Event parsing
# ---------------------------------------------------------------------------

def iter_events(local_path: str) -> Iterator[Dict]:
    """Yield raw event dicts from a ZIP, JSON, or JSONL file."""
    if not local_path or not os.path.exists(local_path):
        return

    if local_path.endswith(".zip"):
        try:
            with zipfile.ZipFile(local_path, "r") as zf:
                for name in zf.namelist():
                    if name.lower().endswith((".json", ".jsonl", ".log")):
                        try:
                            with zf.open(name) as fh:
                                yield from _parse_stream(fh)
                        except Exception as e:
                            logger.debug(f"Error reading {name} in {local_path}: {e}")
        except zipfile.BadZipFile:
            logger.debug(f"Bad ZIP: {local_path}")
    elif local_path.lower().endswith((".json", ".jsonl", ".log")):
        try:
            with open(local_path, "r", encoding="utf-8", errors="replace") as fh:
                yield from _parse_stream(fh)
        except Exception as e:
            logger.debug(f"Error reading {local_path}: {e}")


def _parse_stream(fh) -> Iterator[Dict]:
    """
    Parse a file-like object that is either:
      - A JSON array:  [{...}, {...}, ...]
      - JSONL:         one JSON object per line
    """
    try:
        raw = fh.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        raw = raw.strip()
        if not raw:
            return
        if raw.startswith("["):
            for obj in json.loads(raw):
                if isinstance(obj, dict):
                    yield obj
        else:
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            yield obj
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        logger.debug(f"Stream parse error: {e}")


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build(otrf_base: str, output_path: str, max_events: int) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    random.seed(RANDOM_SEED)

    n_scenarios = 0
    n_events = 0
    n_skipped = 0
    tactic_counts: Dict[str, int] = {}

    with open(output_path, "w", encoding="utf-8") as out:
        for meta in iter_metadata(otrf_base):
            attack_mappings = meta.get("attack_mappings", [])
            tactic = get_tactic_label(attack_mappings)       # primary (backward compat)
            all_tactics = get_tactic_labels(attack_mappings) # all labels (multi-label)
            techniques = get_technique_ids(attack_mappings)
            scenario_id = meta.get("id", "unknown")

            if tactic == "unknown":
                n_skipped += 1
                continue

            # Collect events from all data files in this scenario
            scenario_alerts: List[NormalizedAlert] = []
            for file_info in meta.get("files", []):
                link = file_info.get("link", "")
                local = url_to_local(link, otrf_base)
                if not local:
                    continue
                for raw_event in iter_events(local):
                    try:
                        normalized = auto_normalize(raw_event)
                        # Skip events with no useful text (e.g. pure pcap data)
                        if len(normalized.raw_text.strip()) >= 10:
                            scenario_alerts.append(normalized)
                    except Exception:
                        pass

            if not scenario_alerts:
                n_skipped += 1
                logger.debug(f"No events for scenario {scenario_id}")
                continue

            # Sample to cap per-class imbalance
            if len(scenario_alerts) > max_events:
                scenario_alerts = random.sample(scenario_alerts, max_events)

            # Write labeled records
            for alert in scenario_alerts:
                record = asdict(alert)
                record["tactic"] = tactic            # primary label (single-label compat)
                record["tactics"] = all_tactics      # all labels  (multi-label training)
                record["technique_ids"] = techniques
                record["scenario_id"] = scenario_id
                out.write(json.dumps(record) + "\n")

            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + len(scenario_alerts)
            n_events += len(scenario_alerts)
            n_scenarios += 1
            logger.debug(f"  [{scenario_id}] tactic={tactic} events={len(scenario_alerts)}")

    # Summary
    logger.info("=" * 55)
    logger.info(f"Dataset build complete")
    logger.info(f"  Scenarios processed : {n_scenarios}")
    logger.info(f"  Scenarios skipped   : {n_skipped}")
    logger.info(f"  Total events        : {n_events}")
    logger.info(f"  Output              : {output_path}")
    logger.info("  Events per tactic:")
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        bar = "█" * (count // 20)
        logger.info(f"    {tactic:<28} {count:>5}  {bar}")
    logger.info("=" * 55)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build OTRF labeled dataset")
    parser.add_argument("--otrf-path", default=DEFAULT_OTRF,
                        help="Path to Security-Datasets repo root")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="Output JSONL file path")
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS,
                        help="Max events sampled per scenario")
    args = parser.parse_args()

    if not os.path.exists(args.otrf_path):
        logger.error(f"OTRF dataset not found at: {args.otrf_path}")
        logger.error("Set --otrf-path or OTRF_PATH env variable.")
        sys.exit(1)

    build(args.otrf_path, args.output, args.max_events)

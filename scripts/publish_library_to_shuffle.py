#!/usr/bin/env python3
"""
Publish the CACAO playbook library (playbooks/*.yaml) to Shuffle as reusable workflows,
one per template (core/orchestration_engine/shuffle_library.py; the Playbooks page's
"Sync to Shuffle" button does the same).

Missing workflows are created, changed ones updated (SSH credentials entered in Shuffle
are kept), unchanged ones left alone.

Usage (inside the ai4soar container, which has the Shuffle settings):
    python3 scripts/publish_library_to_shuffle.py            # create / update as needed
    python3 scripts/publish_library_to_shuffle.py --force    # rewrite every workflow
    python3 scripts/publish_library_to_shuffle.py --run      # ... and run each once
    python3 scripts/publish_library_to_shuffle.py t1110      # only matching templates
    python3 scripts/publish_library_to_shuffle.py --status   # only report
    python3 scripts/publish_library_to_shuffle.py --delete   # remove them from Shuffle
"""

import argparse
import json
import logging
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import config                             # noqa: E402
from core.orchestration_engine import shuffle_library      # noqa: E402


def run(wid: str, argument: dict) -> dict:
    s = config.shuffle
    eid = requests.post(f"{s.api_base_url}/workflows/{wid}/execute", headers=s.get_headers(),
                        data=json.dumps(argument), timeout=30).json()["execution_id"]
    for _ in range(60):
        r = requests.post(f"{s.api_base_url}/streams/results", headers=s.get_headers(),
                          json={"execution_id": eid}, timeout=30).json()
        if r.get("status") in ("FINISHED", "ABORTED", "FAILURE"):
            return r
        time.sleep(3)
    return {"status": "TIMEOUT", "results": []}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("only", nargs="*", help="only templates whose file name contains one of these")
    ap.add_argument("--force", action="store_true", help="rewrite workflows even if unchanged")
    ap.add_argument("--run", action="store_true", help="run each workflow once with its example argument")
    ap.add_argument("--status", action="store_true", help="only report what is in Shuffle")
    ap.add_argument("--delete", action="store_true", help="delete the library workflows from Shuffle")
    args = ap.parse_args()
    logging.disable(logging.CRITICAL)

    if args.delete:
        for name in shuffle_library.delete_all():
            print(f"deleted  {name}")
        return
    if args.status:
        for s in shuffle_library.status(args.only):
            print(f"{s['state']:9} {s['file']:34} {s['url'] or ''}")
        return

    results = shuffle_library.sync(args.only, force=args.force)
    by_id = {t["id"]: t for t in shuffle_library.templates(args.only)}
    for r in results:
        print(f"{'OK  ' if r['ok'] else 'FAIL'} {r['action']:9} {r['file']:34} {r['url']}")
        if r.get("kept"):
            print(f"       kept {r['kept']} credential value(s) entered in Shuffle")
        for w in r["warnings"]:
            print(f"       warning: {w}")
        if not r["ok"]:
            print(f"       shuffle: {r.get('error')}")
        if args.run:
            res = run(r["workflow_id"], shuffle_library.example_argument(by_id[r["template_id"]]))
            done = [f"{x['action']['label']}={x['status']}" for x in res.get("results") or []]
            print(f"       run {res.get('status')}: {', '.join(done)}")
    bad = sum(not r["ok"] for r in results)
    print(f"\n{len(results) - bad}/{len(results)} in Shuffle and intact "
          f"({sum(r['action'] == 'created' for r in results)} created, "
          f"{sum(r['action'] == 'updated' for r in results)} updated, "
          f"{sum(r['action'] == 'unchanged' for r in results)} unchanged)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

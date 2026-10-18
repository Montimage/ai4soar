"""
Example alerts shipped with AI4SOAR (data/example_alerts.json): ten Wazuh alerts about
the demo victim web-01 (docker-compose.lab.yml) covering Path A (MITRE technique in the
alert), Path B (the LLM attributes it) and Path D (no template: the LLM writes the
playbook). Listed first on the Alerts page.

load(): inserts the ones missing from the alerts collection, at startup (api/app.py) unless
EXAMPLE_ALERTS=false. Never overwrites: an edited example stays edited; force=True (or
`python3 scripts/load_example_alerts.py --force`) restores them as shipped.
"""

import json
import logging
import os
from typing import Dict, List

from pymongo import MongoClient

from core.config import config

logger = logging.getLogger(__name__)
PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "example_alerts.json")


def alerts() -> List[Dict]:
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


def load(force: bool = False) -> int:
    """Insert the example alerts missing from MongoDB (all of them with force). Returns how many."""
    col = MongoClient(config.mongodb.host, config.mongodb.port, serverSelectionTimeoutMS=3000)[
        config.mongodb.database][config.mongodb.alerts_collection]
    n = 0
    for a in alerts():
        if force:
            col.replace_one({"_id": a["_id"]}, a, upsert=True)
            n += 1
        elif not col.find_one({"_id": a["_id"]}, {"_id": 1}):
            col.insert_one(a)
            n += 1
    return n

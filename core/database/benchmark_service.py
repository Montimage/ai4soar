"""
Benchmark alert service — the curated 37-alert MMT / Suricata / Snort set.

Separate from AlertService (which serves the ~26K historical Wazuh alerts) because the
two answer different questions: historical alerts are production traffic to triage,
benchmark alerts are labelled ground-truth cases for exercising the orchestrator.
Keeping them in their own collection means loading or re-loading the benchmark can
never disturb the operational alert store.

Populate with: python3 scripts/load_benchmark_alerts.py
"""

import logging
from typing import Any, Dict, List

from pymongo import MongoClient

from core.config import config
from core.exceptions import DatabaseError

logger = logging.getLogger(__name__)

# How the alert text is presented to the orchestrator. These are the two modes the
# 37-alert benchmark was scored under (37 × 2 = 74 evaluations).
MODE_VISIBLE  = "visible"    # signature included — what the SIEM actually emits
MODE_STRIPPED = "stripped"   # signature removed — tests attribution from evidence alone
MODES = (MODE_VISIBLE, MODE_STRIPPED)


class BenchmarkAlertService:
    """Read-only access to the benchmark alert collection."""

    def __init__(self) -> None:
        self._client = None
        self._coll = None

    def _collection(self):
        if self._coll is None:
            try:
                self._client = MongoClient(
                    config.mongodb.host,
                    config.mongodb.port,
                    serverSelectionTimeoutMS=5000,
                )
                self._coll = (
                    self._client[config.mongodb.database]
                    [config.mongodb.benchmark_collection]
                )
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB: {e}")
                raise DatabaseError(f"Failed to connect to MongoDB: {e}") from e
        return self._coll

    # ------------------------------------------------------------------
    def list_alerts(self, source_tool: str = "", mode: str = MODE_VISIBLE,
                    search: str = "") -> Dict[str, Any]:
        """
        Return every benchmark alert, optionally filtered by tool or free text.

        `mode` decides what the orchestrator will read: the returned documents are
        rendered for that mode, so whatever the UI hands to /recommend is exactly what
        was listed — no second transformation in the browser.
        """
        coll = self._collection()

        query: Dict[str, Any] = {}
        if source_tool and source_tool != "all":
            query["_benchmark.source_tool"] = source_tool.lower()
        if search:
            rx = {"$regex": search, "$options": "i"}
            query["$or"] = [
                {"rule.description": rx},
                {"_benchmark.note": rx},
                {"_benchmark.ground_truth.technique_ids": rx},
                {"_benchmark.ground_truth.tactic": rx},
            ]

        docs = [self.render(d, mode) for d in coll.find(query).sort("_id", 1)]

        counts = {"all": coll.count_documents({})}
        for tool in coll.distinct("_benchmark.source_tool"):
            counts[tool] = coll.count_documents({"_benchmark.source_tool": tool})

        return {"alerts": docs, "total": len(docs), "counts": counts, "mode": mode}

    @staticmethod
    def render(doc: Dict[str, Any], mode: str = MODE_VISIBLE) -> Dict[str, Any]:
        """Project a stored document into the alert the orchestrator should receive.

        In stripped mode the detection signature is removed from BOTH places it appears
        — rule.description and data.raw_text — because alert_to_text() feeds both to the
        model, and leaving either one behind would quietly turn a stripped run back into
        a visible one.
        """
        out = dict(doc)
        bench = out.get("_benchmark", {}) or {}
        texts = bench.get("text", {}) or {}

        if mode == MODE_STRIPPED:
            out["rule"] = {**out.get("rule", {}), "description": ""}
            out["data"] = {**out.get("data", {}),
                           "raw_text": texts.get("stripped", "")}
        else:
            out["rule"] = {**out.get("rule", {}),
                           "description": bench.get("signature", "")}
            out["data"] = {**out.get("data", {}),
                           "raw_text": texts.get("visible", "")}
        out["_mode"] = mode
        return out

    def get(self, alert_id: str, mode: str = MODE_VISIBLE) -> Dict[str, Any]:
        doc = self._collection().find_one({"_id": alert_id})
        return self.render(doc, mode) if doc else {}

    def stats(self) -> Dict[str, Any]:
        """Counts by tool and by tactic — what the dataset actually covers."""
        coll = self._collection()
        total = coll.count_documents({})
        by_tool = {
            t: coll.count_documents({"_benchmark.source_tool": t})
            for t in sorted(coll.distinct("_benchmark.source_tool"))
        }
        by_tactic: Dict[str, int] = {}
        for tactic in coll.distinct("_benchmark.ground_truth.tactic"):
            by_tactic[tactic] = coll.count_documents(
                {"_benchmark.ground_truth.tactic": tactic}
            )
        return {
            "total":       total,
            "by_tool":     by_tool,
            "by_tactic":   dict(sorted(by_tactic.items(), key=lambda kv: -kv[1])),
            "techniques":  len(coll.distinct("_benchmark.ground_truth.technique_ids")),
            "loaded":      total > 0,
            "collection":  config.mongodb.benchmark_collection,
        }


benchmark_service = BenchmarkAlertService()

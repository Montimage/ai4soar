"""
MMT (Montimage Monitoring Tool) alert adapter.

Handles the MMT JSON format published to NATS/Kafka:
  {
    "type":    "flow" | "security" | ...,
    "payload": {
      "probeId":     <int>,
      "timestamp":   <unix seconds>,
      "code":        <int>,
      "status":      "detected" | ...,
      "category":    "attack" | "anomaly" | ...,
      "description": "<human-readable>",
      "srcIp":       "<ip>",
      "dstIp":       "<ip>",
      "details":     { ... }
    }
  }

This adapter handles FORMAT NORMALIZATION only — it maps MMT fields to the
canonical _source envelope so the rest of the pipeline sees a uniform shape.

MITRE attribution is intentionally left empty here. When no explicit T-codes
are present in the source alert, the orchestrator routes to Path B (LLM) and
Path C (ML) to infer the technique from the alert description.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from .base import AlertAdapter

_CATEGORY_LEVEL: Dict[str, int] = {
    'attack':  12,
    'anomaly':  7,
    'warning':  5,
    'info':     3,
}


def _unix_to_iso(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return str(ts)


class MMTAdapter(AlertAdapter):

    @property
    def name(self) -> str:
        return "mmt"

    def can_handle(self, alert: Dict[str, Any]) -> bool:
        return (
            isinstance(alert.get("type"), str)
            and "payload" in alert
            and isinstance(alert.get("payload"), dict)
        )

    def normalize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        p = alert["payload"]

        probe_id    = p.get("probeId", 0)
        timestamp   = p.get("timestamp", 0)
        code        = p.get("code", 0)
        status      = p.get("status", "")
        category    = p.get("category", "")
        description = p.get("description", "")
        src_ip      = p.get("srcIp", "")
        dst_ip      = p.get("dstIp", "")

        return {
            "_index":  "mmt-alerts",
            "_id":     f"mmt-{probe_id}-{timestamp}-{code}",
            "_source": {
                "timestamp": _unix_to_iso(timestamp),
                "agent": {
                    "id":   str(probe_id),
                    "name": f"mmt-probe-{probe_id}",
                },
                "rule": {
                    "id":          str(code),
                    "level":       _CATEGORY_LEVEL.get(category.lower(), 5),
                    "description": description,
                    "groups":      [category, status, alert.get("type", "")],
                    "mitre":       {},   # no T-codes in MMT — Path B/C will infer
                },
                "data": {
                    "srcip":    src_ip,
                    "dstip":    dst_ip,
                    "category": category,
                    "status":   status,
                    "code":     code,
                    "probe_id": probe_id,
                },
            },
            "_adapter": self.name,
            "_raw":     alert,
        }

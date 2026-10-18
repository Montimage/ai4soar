"""
Wazuh / OpenSearch alert adapter.

Handles the standard Wazuh Elasticsearch document format:
  alert["_source"]["rule"]["mitre"]  — technique IDs, names, tactics
  alert["_source"]["data"]           — network fields
  alert["_source"]["agent"]          — host information
and the raw alert as the Wazuh manager writes it (alerts.json, or forwarded as is): the
same fields at the top level, recognised by rule.id + rule.level and a manager, decoder
or location field. It is wrapped in the _source envelope, so its rule.mitre techniques
reach Path A like those of an indexed alert.
"""

from typing import Any, Dict

from .base import AlertAdapter


class WazuhAdapter(AlertAdapter):

    @property
    def name(self) -> str:
        return "wazuh"

    def can_handle(self, alert: Dict[str, Any]) -> bool:
        return ("_source" in alert and "rule" in alert.get("_source", {})) or _raw_wazuh(alert)

    def normalize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        if "_source" not in alert:
            # Raw manager alert: the envelope the rest of the pipeline reads
            return {"_id": alert.get("_id") or alert.get("id"), "_source": dict(alert),
                    "_adapter": self.name, "_raw": alert}
        # Already in canonical shape — just tag it and preserve original.
        out = dict(alert)
        out["_adapter"] = self.name
        out.setdefault("_raw", alert)
        return out


def _raw_wazuh(alert: Dict[str, Any]) -> bool:
    rule = alert.get("rule")
    return (isinstance(rule, dict) and "id" in rule and "level" in rule
            and any(k in alert for k in ("manager", "decoder", "location")))

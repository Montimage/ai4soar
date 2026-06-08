"""
Wazuh / OpenSearch alert adapter.

Handles the standard Wazuh Elasticsearch document format:
  alert["_source"]["rule"]["mitre"]  — technique IDs, names, tactics
  alert["_source"]["data"]           — network fields
  alert["_source"]["agent"]          — host information
"""

from typing import Any, Dict

from .base import AlertAdapter


class WazuhAdapter(AlertAdapter):

    @property
    def name(self) -> str:
        return "wazuh"

    def can_handle(self, alert: Dict[str, Any]) -> bool:
        return "_source" in alert and "rule" in alert.get("_source", {})

    def normalize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        # Already in canonical shape — just tag it and preserve original.
        out = dict(alert)
        out["_adapter"] = self.name
        out.setdefault("_raw", alert)
        return out

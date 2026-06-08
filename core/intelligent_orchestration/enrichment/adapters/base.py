"""
Base class for alert format adapters.

An adapter converts a vendor-specific alert structure into the canonical
AI4SOAR envelope so that the enrichment pipeline, MITRE extractor, and
display layer all receive a consistent shape regardless of source.

Canonical envelope shape (Wazuh-compatible):
{
  "_index":  "<source>-alerts",
  "_id":     "<unique-id>",
  "_source": {
    "timestamp": "<ISO-8601>",
    "agent":     {"id": "<id>", "name": "<hostname>"},
    "rule": {
      "id":          "<rule-id>",
      "level":       <int 0-15>,
      "description": "<human-readable description>",
      "groups":      ["<group>", ...],
      "mitre": {
        "id":        ["T1234", ...],   # technique IDs
        "technique": ["<name>", ...],
        "tactic":    ["<tactic>", ...]
      }
    },
    "data": {
      "srcip":  "<ip>",
      "dstip":  "<ip>",
      ...
    }
  },
  "_adapter": "<adapter-name>",   # set by normalize()
  "_raw":     { ... }             # original alert, preserved verbatim
}
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class AlertAdapter(ABC):
    """Abstract base for all alert format adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used for logging and source_format tagging."""

    @abstractmethod
    def can_handle(self, alert: Dict[str, Any]) -> bool:
        """Return True if this adapter recognises the alert's format."""

    @abstractmethod
    def normalize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert alert to the canonical envelope.
        Must set `_adapter` and `_raw` on the returned dict.
        Should never raise — return a best-effort envelope on partial data.
        """

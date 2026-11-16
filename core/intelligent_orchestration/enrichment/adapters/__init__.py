"""
Alert format adapter registry.

Adapters are tried in order — first match wins.
Add new adapters here to extend format support.
"""

from .mmt import MMTAdapter
from .mmt_probe import MMTProbeAdapter
from .wazuh import WazuhAdapter

# Order matters: most-specific format first.
ADAPTERS = [
    MMTProbeAdapter(),   # native mmt-probe reports: CSV text, JSON array, STIX bundle
    MMTAdapter(),
    WazuhAdapter(),
]

__all__ = ["ADAPTERS", "MMTAdapter", "MMTProbeAdapter", "WazuhAdapter"]

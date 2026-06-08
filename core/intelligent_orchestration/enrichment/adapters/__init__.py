"""
Alert format adapter registry.

Adapters are tried in order — first match wins.
Add new adapters here to extend format support.
"""

from .mmt import MMTAdapter
from .wazuh import WazuhAdapter

# Order matters: most-specific format first.
ADAPTERS = [
    MMTAdapter(),
    WazuhAdapter(),
]

__all__ = ["ADAPTERS", "MMTAdapter", "WazuhAdapter"]

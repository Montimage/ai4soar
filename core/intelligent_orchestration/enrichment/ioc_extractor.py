"""
IOCExtractor — pulls concrete observables from an alert dict.

Supports Wazuh, ECS, and generic alert formats by trying multiple
dot-notation paths for each canonical IOC name.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# canonical IOC name → ordered list of dot-notation paths to try in the alert
_IOC_PATHS: Dict[str, List[str]] = {
    "src_ip": [
        "_source.data.srcip",
        "data.srcip",
        "_source.srcip",
        "srcip",
        "_source.source.ip",
        "_source.network.forwarded_ip",
    ],
    "dst_ip": [
        "_source.data.dstip",
        "data.dstip",
        "_source.dstip",
        "dstip",
        "_source.destination.ip",
    ],
    "src_port": [
        "_source.data.srcport",
        "data.srcport",
        "_source.source.port",
    ],
    "dst_port": [
        "_source.data.dstport",
        "data.dstport",
        "_source.destination.port",
    ],
    "username": [
        "_source.data.dstuser",
        "data.dstuser",
        "_source.data.win.eventdata.subjectUserName",
        "_source.data.user",
        "data.user",
    ],
    "hostname": [
        "_source.agent.name",
        "agent.name",
        "_source.hostname",
        "hostname",
    ],
    "agent_ip": [
        "_source.agent.ip",
        "agent.ip",
    ],
    "process_name": [
        "_source.data.win.eventdata.image",
        "_source.data.process.name",
        "data.process.name",
    ],
    "file_path": [
        "_source.syscheck.path",
        "_source.data.win.eventdata.targetFilename",
        "data.file.path",
    ],
    "url": [
        "_source.data.url",
        "data.url",
    ],
    "domain": [
        "_source.data.domain",
        "data.domain",
    ],
    "email_sender": [
        "_source.data.email.from",
        "data.email.from",
        "_source.data.srcuser",
        "data.srcuser",
    ],
    "email_subject": [
        "_source.data.email.subject",
        "data.email.subject",
    ],
    "hash_md5": [
        "_source.syscheck.md5_after",
        "data.hash.md5",
    ],
    "hash_sha256": [
        "_source.syscheck.sha256_after",
        "data.hash.sha256",
    ],
    "protocol": [
        "_source.data.protocol",
        "data.protocol",
    ],
}


class IOCExtractor:
    """Extracts IOCs from an alert dict into a flat canonical dict."""

    def extract(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        iocs: Dict[str, Any] = {}
        for ioc_name, paths in _IOC_PATHS.items():
            value = _resolve(alert, paths)
            if value is not None:
                iocs[ioc_name] = value
        logger.debug(f"[IOCExtractor] {len(iocs)} IOCs: {list(iocs.keys())}")
        return iocs


def _resolve(alert: Dict, paths: List[str]) -> Optional[Any]:
    for path in paths:
        value = _get_nested(alert, path.split("."))
        if value is not None and value != "":
            return value
    return None


def _get_nested(obj: Any, keys: List[str]) -> Optional[Any]:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj

"""
Format-agnostic alert normalizer for AI4SOAR.

Converts any alert format (Wazuh JSON, OTRF Windows Events, Zeek logs)
into a unified NormalizedAlert schema used by the feature engineer.

Generalization strategy: NormalizedAlert contains ONLY semantic/behavioral
fields — never format-specific IDs like EventID or Wazuh rule.id. This
ensures a model trained on OTRF Windows logs generalizes to Wazuh SSH alerts.
"""

import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core schema
# ---------------------------------------------------------------------------

@dataclass
class NormalizedAlert:
    """
    Format-agnostic alert representation.

    Fields are derived WITHOUT using MITRE tags (rule.mitre.*) because:
    - Path A already handles alerts that have MITRE tags.
    - Path B must predict playbooks using everything *except* MITRE tags,
      so the model generalises to alerts that Wazuh failed to tag.
    """
    # Human-readable log content (most discriminative feature for text model)
    raw_text: str = ""

    # Coarse behavioral category — same meaning across all formats
    # Values: auth | network | process | file | lateral | discovery | unknown
    event_type: str = "unknown"

    # Severity normalized to [0.0, 1.0]
    severity: float = 0.0

    # Network context flags (format-agnostic booleans)
    src_is_private: bool = False
    dst_is_private: bool = False

    # Port semantic range: well-known | registered | ephemeral | unknown
    src_port_range: str = "unknown"

    # Presence flags (non-specific: just is-there-a-user, is-there-a-process, ...)
    has_user: bool = False
    has_network: bool = False
    has_process: bool = False

    # Which normalizer produced this (metadata only, not used as a feature)
    source_format: str = "unknown"


# ---------------------------------------------------------------------------
# Normalizer base
# ---------------------------------------------------------------------------

class BaseNormalizer(ABC):
    """Abstract base — one subclass per alert format."""

    @abstractmethod
    def can_handle(self, alert: Dict[str, Any]) -> bool:
        """Return True if this normalizer can process the given alert dict."""

    @abstractmethod
    def normalize(self, alert: Dict[str, Any]) -> NormalizedAlert:
        """Convert alert dict → NormalizedAlert."""


# ---------------------------------------------------------------------------
# Wazuh normalizer
# ---------------------------------------------------------------------------

class WazuhNormalizer(BaseNormalizer):
    """
    Handles Wazuh Elasticsearch document format:
      alert["_source"]["rule"], alert["_source"]["data"], etc.
    """

    _GROUP_TO_TYPE = {
        "authentication_failed": "auth",
        "authentication_success": "auth",
        "brute_force": "auth",
        "sshd": "auth",
        "pam": "auth",
        "sudo": "auth",
        "web": "network",
        "firewall": "network",
        "ids": "network",
        "network": "network",
        "attack": "network",    # MMT alert category
        "anomaly": "network",   # MMT alert category
        "process": "process",
        "syscheck": "file",
        "rootcheck": "process",
        "discovery": "discovery",
        "lateral_movement": "lateral",
    }

    def can_handle(self, alert: Dict[str, Any]) -> bool:
        src = alert.get("_source", {})
        return isinstance(src, dict) and "rule" in src

    def normalize(self, alert: Dict[str, Any]) -> NormalizedAlert:
        source = alert.get("_source", {})
        rule = source.get("rule", {})
        data = source.get("data", {})
        predecoder = source.get("predecoder", {})

        # --- raw_text: most important field ---
        parts: List[str] = []
        if source.get("full_log"):
            parts.append(source["full_log"])
        if rule.get("description"):
            parts.append(rule["description"])
        program = predecoder.get("program_name", "")
        if program:
            parts.append(f"program:{program}")
        raw_text = " | ".join(parts)

        # --- event_type from rule groups ---
        groups = rule.get("groups", [])
        event_type = "unknown"
        for g in groups:
            et = self._GROUP_TO_TYPE.get(g.lower())
            if et:
                event_type = et
                break
        # fallback via program name
        if event_type == "unknown" and program:
            p = program.lower()
            if "ssh" in p or "pam" in p or "login" in p:
                event_type = "auth"
            elif "apache" in p or "nginx" in p or "http" in p:
                event_type = "network"

        # --- severity ---
        severity = min(rule.get("level", 0) / 15.0, 1.0)

        # --- network ---
        srcip = data.get("srcip", "")
        dstip = data.get("dstip", "")
        srcport = str(data.get("srcport", ""))

        return NormalizedAlert(
            raw_text=raw_text,
            event_type=event_type,
            severity=severity,
            src_is_private=_is_private(srcip),
            dst_is_private=_is_private(dstip),
            src_port_range=_port_range(srcport),
            has_user=bool(data.get("dstuser") or data.get("srcuser")),
            has_network=bool(srcip or dstip),
            has_process=False,
            source_format="wazuh",
        )


# ---------------------------------------------------------------------------
# OTRF Windows Event normalizer
# ---------------------------------------------------------------------------

class OTRFWindowsEventNormalizer(BaseNormalizer):
    """
    Handles OTRF Windows Event Log JSON format (Sysmon + Security events).
    Fields: EventID, Message, Image, CommandLine, AccountName,
            SourceAddress, DestAddress, SourcePort, Hostname, etc.
    """

    # Sysmon EventIDs → semantic type
    _EID_TYPE: Dict[int, str] = {
        # Auth / credential
        4624: "auth", 4625: "auth", 4648: "auth",
        4768: "auth", 4769: "auth", 4771: "auth",
        4776: "auth", 4634: "auth", 4672: "auth",
        4738: "auth", 4740: "auth",
        # Process creation / termination
        1: "process", 4688: "process", 4689: "process", 5: "process",
        # Network connection
        3: "network", 5156: "network", 5158: "network",
        # File
        11: "file", 23: "file", 4663: "file", 4656: "file",
        # Registry (treat as process context)
        12: "process", 13: "process", 14: "process",
        # Named pipe / lateral movement indicators
        17: "lateral", 18: "lateral",
        # DNS
        22: "network",
        # WMI
        19: "process", 20: "process", 21: "process",
        # Discovery
        4798: "discovery", 4799: "discovery",
        # Logon lateral
        4771: "lateral",
    }

    def can_handle(self, alert: Dict[str, Any]) -> bool:
        return "EventID" in alert and (
            "Message" in alert or "Channel" in alert or "SourceName" in alert
        )

    def normalize(self, alert: Dict[str, Any]) -> NormalizedAlert:
        event_id = int(alert.get("EventID", 0))

        # --- raw_text: combine the most informative text fields ---
        # Prepend EventID as a semantic keyword — strong discriminative signal:
        # e.g. eventid_4625 (failed logon) vs eventid_4688 (process create)
        # vs eventid_17 (named pipe, lateral movement).
        parts: List[str] = [f"eventid_{event_id}"]
        msg = alert.get("Message", "")
        if msg:
            # first 400 chars — enough for semantics, avoids memory bloat
            parts.append(str(msg)[:400])
        for field in ("CommandLine", "Image", "Details", "TargetObject",
                      "TargetFilename", "Description"):
            val = alert.get(field)
            if val and val not in ("-", ""):
                parts.append(f"{field.lower()}:{str(val)[:120]}")
        channel = alert.get("Channel", "")
        if channel:
            parts.append(f"channel:{channel}")
        raw_text = " | ".join(parts)

        # --- event_type ---
        event_type = self._EID_TYPE.get(event_id, "unknown")

        # --- severity from SeverityValue (1=DEBUG,2=INFO,3=WARN,4=ERROR,5=CRIT) ---
        sev_val = int(alert.get("SeverityValue", 2))
        severity = min((sev_val - 1) / 4.0, 1.0)

        # --- network ---
        src_ip = (alert.get("SourceAddress") or alert.get("IpAddress") or
                  alert.get("id_orig_h", ""))
        dst_ip = (alert.get("DestAddress") or alert.get("DestinationIp", ""))
        src_port = str(alert.get("SourcePort") or alert.get("id_orig_p", ""))

        # --- user presence ---
        user = (alert.get("SubjectUserName") or alert.get("TargetUserName") or
                alert.get("AccountName") or "")
        has_user = bool(user and user.strip() not in ("-", "SYSTEM", "", "LOCAL SERVICE"))

        # --- process presence ---
        has_process = bool(
            alert.get("Image") or alert.get("CommandLine") or
            alert.get("ProcessId")
        )

        return NormalizedAlert(
            raw_text=raw_text,
            event_type=event_type,
            severity=severity,
            src_is_private=_is_private(src_ip),
            dst_is_private=_is_private(dst_ip),
            src_port_range=_port_range(src_port),
            has_user=has_user,
            has_network=bool(src_ip or dst_ip),
            has_process=has_process,
            source_format="otrf_windows",
        )


# ---------------------------------------------------------------------------
# OTRF Zeek log normalizer
# ---------------------------------------------------------------------------

class OTRFZeekLogNormalizer(BaseNormalizer):
    """
    Handles OTRF Zeek network log JSON format.
    Field @stream indicates log type: conn, dns, kerberos, smb_mapping, etc.
    """

    _STREAM_TYPE: Dict[str, str] = {
        "conn": "network",   "dns": "network",
        "http": "network",   "ssl": "network",
        "x509": "network",   "notice": "network",
        "kerberos": "auth",  "ntlm": "auth",
        "ssh": "auth",       "ftp": "auth",
        "smb_mapping": "lateral", "smb_files": "lateral",
        "rdp": "lateral",    "dce_rpc": "lateral",
        "weird": "network",
    }

    def can_handle(self, alert: Dict[str, Any]) -> bool:
        return "@stream" in alert and "ts" in alert

    def normalize(self, alert: Dict[str, Any]) -> NormalizedAlert:
        stream = alert.get("@stream", "")

        # Build synthetic text from protocol semantics
        parts = [f"zeek {stream}"]
        for field in ("service", "proto", "request_type", "client",
                      "method", "uri", "path", "query", "conn_state",
                      "cipher", "subject"):
            val = alert.get(field)
            if val:
                parts.append(f"{field}:{str(val)[:80]}")
        # Failure indicators
        if alert.get("success") is False:
            parts.append("failed")
        if alert.get("conn_state") in ("REJ", "RSTOS0", "RSTRH", "S0"):
            parts.append("rejected")
        raw_text = " | ".join(parts)

        event_type = self._STREAM_TYPE.get(stream, "network")

        # Heuristic severity
        severity = 0.3
        if alert.get("conn_state") in ("REJ", "RSTOS0", "RSTRH"):
            severity = 0.6
        if alert.get("success") is False:
            severity = 0.65

        src_ip = str(alert.get("id_orig_h", ""))
        dst_ip = str(alert.get("id_resp_h", ""))
        src_port = str(alert.get("id_orig_p", ""))

        has_user = bool(
            alert.get("client") or alert.get("user") or
            alert.get("username") or alert.get("subject")
        )

        return NormalizedAlert(
            raw_text=raw_text,
            event_type=event_type,
            severity=severity,
            src_is_private=_is_private(src_ip),
            dst_is_private=_is_private(dst_ip),
            src_port_range=_port_range(src_port),
            has_user=has_user,
            has_network=True,
            has_process=False,
            source_format="otrf_zeek",
        )


# ---------------------------------------------------------------------------
# Auto-detect dispatcher
# ---------------------------------------------------------------------------

_NORMALIZERS: List[BaseNormalizer] = [
    WazuhNormalizer(),
    OTRFWindowsEventNormalizer(),
    OTRFZeekLogNormalizer(),
]


def auto_normalize(alert: Dict[str, Any]) -> NormalizedAlert:
    """
    Auto-detect format and return a NormalizedAlert.
    Falls back to a minimal text extraction if no normalizer matches.
    This ensures the pipeline never crashes on unknown alert formats.
    """
    for normalizer in _NORMALIZERS:
        try:
            if normalizer.can_handle(alert):
                return normalizer.normalize(alert)
        except Exception as e:
            logger.debug(f"{normalizer.__class__.__name__} failed: {e}")
            continue

    # Generic fallback: stringify all string values
    logger.debug(f"No normalizer matched. Keys: {list(alert.keys())[:8]}")
    raw = " ".join(
        str(v) for v in alert.values()
        if isinstance(v, (str, int, float)) and str(v) not in ("-", "")
    )[:500]
    return NormalizedAlert(raw_text=raw, source_format="generic")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private(ip_str: str) -> bool:
    if not ip_str or ip_str in ("-", "::1", "127.0.0.1", "0.0.0.0", ""):
        return True
    try:
        return ipaddress.ip_address(ip_str.strip()).is_private
    except ValueError:
        return False


def _port_range(port_str: str) -> str:
    try:
        port = int(str(port_str).strip())
        if 0 < port < 1024:
            return "well-known"
        elif 1024 <= port < 49152:
            return "registered"
        elif port >= 49152:
            return "ephemeral"
    except (ValueError, TypeError):
        pass
    return "unknown"

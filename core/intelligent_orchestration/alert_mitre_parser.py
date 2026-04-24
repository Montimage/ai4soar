"""
Multi-format MITRE tag extractor for AI4SOAR Path A (direct STIX lookup).

Handles every alert format that carries MITRE ATT&CK tags inline:
  - Wazuh (Elasticsearch document)
  - Elastic Common Schema (ECS)
  - Microsoft Sentinel (SecurityAlert)
  - CrowdStrike Falcon detection
  - OTRF YAML-labeled event (research/evaluation only)

For formats WITHOUT MITRE tags (raw Windows events, syslog, Zeek),
returns an empty MITREContext and the caller falls back to Path B (ML).

Usage:
    from core.intelligent_orchestration.alert_mitre_parser import extract_mitre_context
    ctx = extract_mitre_context(alert_dict)
    if ctx.has_tags:
        playbooks = kb.get_playbooks_for_technique(ctx.technique_ids[0])
    else:
        # fall back to ML recommendation
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Matches T1110, T1110.003, T0000 etc.
_TCODE_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')


@dataclass
class MITREContext:
    """Normalised MITRE ATT&CK context extracted from any alert format."""
    technique_ids:    List[str] = field(default_factory=list)   # ["T1110.003"]
    technique_names:  List[str] = field(default_factory=list)   # ["Password Spraying"]
    tactic_names:     List[str] = field(default_factory=list)   # ["credential-access"]
    source_format:    str = "unknown"
    raw_alert:        Optional[Dict] = field(default=None, repr=False)

    @property
    def has_tags(self) -> bool:
        """True if at least one technique ID was found."""
        return bool(self.technique_ids)

    def summary(self) -> str:
        if not self.has_tags:
            return f"[{self.source_format}] NO MITRE TAG → Path B required"
        return (
            f"[{self.source_format}] "
            f"techniques={self.technique_ids}  "
            f"tactics={self.tactic_names}"
        )


# ---------------------------------------------------------------------------
# Format detectors + extractors
# ---------------------------------------------------------------------------

def _parse_wazuh(alert: Dict) -> Optional[MITREContext]:
    """
    Wazuh Elasticsearch document format.
      alert["_source"]["rule"]["mitre"]["id"]
      alert["_source"]["rule"]["mitre"]["technique"]
      alert["_source"]["rule"]["mitre"]["tactic"]
    """
    src = alert.get("_source", {})
    if not isinstance(src, dict) or "rule" not in src:
        return None
    mitre = src["rule"].get("mitre", {})
    if not mitre:
        return None
    return MITREContext(
        technique_ids=list(mitre.get("id", [])),
        technique_names=list(mitre.get("technique", [])),
        tactic_names=list(mitre.get("tactic", [])),
        source_format="wazuh",
        raw_alert=alert,
    )


def _parse_ecs(alert: Dict) -> Optional[MITREContext]:
    """
    Elastic Common Schema (ECS) format used by Elastic SIEM / Elasticsearch.
      alert["threat"]["technique"]["id"]   → list of T-codes
      alert["threat"]["technique"]["name"] → list of names
      alert["threat"]["tactic"]["name"]    → list of tactic names
    ECS nests these under a "threat" array or dict.
    """
    threat = alert.get("threat")
    if not threat:
        return None

    # threat can be a dict or list of dicts
    threats = threat if isinstance(threat, list) else [threat]

    tech_ids, tech_names, tactic_names = [], [], []
    for t in threats:
        technique = t.get("technique", {})
        tactic    = t.get("tactic", {})
        # Each sub-field may be a list or scalar
        ids = technique.get("id", [])
        tech_ids.extend(ids if isinstance(ids, list) else [ids])
        names = technique.get("name", [])
        tech_names.extend(names if isinstance(names, list) else [names])
        tnames = tactic.get("name", [])
        tactic_names.extend(tnames if isinstance(tnames, list) else [tnames])

    if not tech_ids:
        return None
    return MITREContext(
        technique_ids=[t for t in tech_ids if t],
        technique_names=[n for n in tech_names if n],
        tactic_names=[n for n in tactic_names if n],
        source_format="elastic_ecs",
        raw_alert=alert,
    )


def _parse_sentinel(alert: Dict) -> Optional[MITREContext]:
    """
    Microsoft Sentinel SecurityAlert table format.
      alert["Techniques"] → ["T1518", ...]
      alert["Tactics"]    → ["Discovery", ...]
    """
    techs = alert.get("Techniques") or alert.get("techniques")
    if not techs:
        return None
    tactics = alert.get("Tactics") or alert.get("tactics") or []
    if isinstance(techs, str):
        techs = [t.strip() for t in techs.split(",")]
    if isinstance(tactics, str):
        tactics = [t.strip() for t in tactics.split(",")]
    # Sentinel tactic names use Title Case, normalise to lowercase-hyphen
    tactic_names = [t.lower().replace(" ", "-") for t in tactics if t]
    return MITREContext(
        technique_ids=[t for t in techs if _TCODE_RE.match(t)],
        technique_names=[],
        tactic_names=tactic_names,
        source_format="sentinel",
        raw_alert=alert,
    )


def _parse_crowdstrike(alert: Dict) -> Optional[MITREContext]:
    """
    CrowdStrike Falcon detection event format.
      alert["technique_id"] → "T1518"
      alert["technique"]    → "Software Discovery"
      alert["tactic"]       → "Discovery"
      alert["tactic_id"]    → "TA0007"
    """
    tid = alert.get("technique_id") or alert.get("TechniqueId")
    if not tid or not _TCODE_RE.match(str(tid)):
        return None
    tactic = alert.get("tactic") or alert.get("Tactic") or ""
    return MITREContext(
        technique_ids=[tid],
        technique_names=[alert.get("technique") or alert.get("Technique") or ""],
        tactic_names=[tactic.lower().replace(" ", "-")] if tactic else [],
        source_format="crowdstrike",
        raw_alert=alert,
    )


def _parse_sigma_match(alert: Dict) -> Optional[MITREContext]:
    """
    Sigma rule match output (e.g. from sigma-cli or Hayabusa).
    Sigma rules carry tags like ["attack.T1518", "attack.discovery"].
      alert["tags"] → ["attack.T1518", "attack.discovery"]
    """
    tags = alert.get("tags") or alert.get("Tags") or []
    if not tags:
        return None
    tech_ids, tactic_names = [], []
    for tag in tags:
        tag = str(tag).lower().strip()
        if tag.startswith("attack.t"):
            candidate = tag.replace("attack.", "").upper()
            if _TCODE_RE.match(candidate):
                tech_ids.append(candidate)
        elif tag.startswith("attack."):
            tactic_names.append(tag.replace("attack.", ""))
    if not tech_ids:
        return None
    return MITREContext(
        technique_ids=tech_ids,
        technique_names=[],
        tactic_names=tactic_names,
        source_format="sigma",
        raw_alert=alert,
    )


def _parse_generic_scan(alert: Dict) -> Optional[MITREContext]:
    """
    Last-resort: scan all string values in the alert for T-code patterns.
    Catches custom/unknown formats that still embed T-codes somewhere.
    """
    found_ids = []
    def _scan(obj: Any, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(obj, str):
            found_ids.extend(_TCODE_RE.findall(obj))
        elif isinstance(obj, dict):
            for v in obj.values():
                _scan(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _scan(item, depth + 1)

    _scan(alert)
    unique = list(dict.fromkeys(found_ids))   # preserve order, deduplicate
    if not unique:
        return None
    logger.debug(f"Generic T-code scan found: {unique}")
    return MITREContext(
        technique_ids=unique,
        technique_names=[],
        tactic_names=[],
        source_format="generic_scan",
        raw_alert=alert,
    )


# Ordered list: most specific first, generic scan last
_PARSERS = [
    _parse_wazuh,
    _parse_ecs,
    _parse_sentinel,
    _parse_crowdstrike,
    _parse_sigma_match,
    _parse_generic_scan,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_mitre_context(alert: Dict[str, Any]) -> MITREContext:
    """
    Auto-detect alert format and extract MITRE ATT&CK context.

    Returns a MITREContext. Check .has_tags to decide between Path A and Path B:

        ctx = extract_mitre_context(alert)
        if ctx.has_tags:
            # Path A: direct STIX lookup
            playbooks = kb.get_playbooks_for_technique(ctx.technique_ids[0])
        else:
            # Path B: ML inference
            playbooks = ml_recommender.recommend(alert)
    """
    for parser in _PARSERS:
        try:
            result = parser(alert)
            if result and result.has_tags:
                logger.debug(f"Parsed as {result.source_format}: {result.technique_ids}")
                return result
        except Exception as e:
            logger.debug(f"Parser {parser.__name__} raised: {e}")
            continue

    # No MITRE tags found in any format
    return MITREContext(source_format="untagged", raw_alert=alert)

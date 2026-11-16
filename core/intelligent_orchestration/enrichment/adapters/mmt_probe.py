"""
MMT-Probe native security-alert adapter.

mmt-probe publishes each security alert (report type 10) to Kafka / file in
one of three shapes, depending on its build and configuration:

  1. CSV text (default, ``output.format=CSV``)::

       10,<probe-id>,"<source>",<ts.us>,<rule-id>,"<verdict>","<type>","<description>",{<event trace JSON>}

  2. JSON array (``output.format=JSON``): the same fields as a JSON list::

       [10,<probe-id>,"<source>",<ts.us>,<rule-id>,"<verdict>","<type>","<description>",{...}]

  3. STIX 2.1 bundle (probe built with ``STIX_FORMAT``): ``identity`` (probe id in
     ``x-probe-id-ext``), ``observed-data`` (time, description), ``ipv4-addr`` /
     ``mac-addr`` SCOs, and an ``x-attack-type`` SDO whose external reference
     ``mmt-security`` carries the rule id.

All three are normalized to the same canonical envelope as ``MMTAdapter`` so the
rest of the pipeline (MITRE extraction, Paths A/B/C, MongoDB) sees one shape.
Like ``MMTAdapter`` it leaves MITRE empty: MMT rules carry no T-codes.

Priority (forward compatible, Montimage/mmt-probe#24): when an alert carries a
``priority`` (critical / high / medium / low) it sets ``rule.level`` (15 / 12 /
7 / 3). In STIX it is read, with ``verdict`` and ``rule_type``, from the
properties of the ``x-attack-type-ext`` extension (STIX only). Otherwise, and
always for CSV / JSON, the level comes from the rule type, as before (STIX
bundles without ``rule_type`` count as ``attack``, 12).

``_id``: ``mmt-{probe}-{ts}-{rule}`` for CSV / JSON (microsecond timestamps).
STIX times have millisecond precision, so the bundle UUID is appended
(``mmt-{probe}-{ts}-{rule}-{uuid}``): two alerts of one rule in the same ms no
longer overwrite each other, and replaying the same message still upserts the
same document.

Other probe reports (type 1 version, 100 session, ...) are not alerts:
``decode_message`` returns None for them so listeners skip them.
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .base import AlertAdapter

SECURITY_REPORT = 10

# Same scale as MMTAdapter (_CATEGORY_LEVEL), keyed on the rule type field.
_TYPE_LEVEL: Dict[str, int] = {
    'attack':    12,
    'evasion':   10,
    'anomaly':    7,
    'warning':    5,
    'security':   5,
    'info':       3,
}
# STIX bundles without rule_type: an x-attack-type object means an attack rule.
_STIX_DEFAULT_TYPE = 'attack'
_STIX_DEFAULT_VERDICT = 'detected'

# Alert priority (mmt-probe#24) -> rule.level; it wins over the rule-type level.
_PRIORITY_LEVEL: Dict[str, int] = {
    'critical': 15,
    'high':     12,
    'medium':    7,
    'low':       3,
}


def _priority(value: Any) -> str:
    """Normalized priority, or '' when absent / not one of the known values."""
    p = value.strip().lower() if isinstance(value, str) else ''
    return p if p in _PRIORITY_LEVEL else ''


def _level(priority: str, rtype: str) -> int:
    if priority:
        return _PRIORITY_LEVEL[priority]
    return _TYPE_LEVEL.get(rtype.lower(), 5)


# ---------------------------------------------------------------------------
# Message decoding (for Kafka / NATS listeners, before any adapter runs)
# ---------------------------------------------------------------------------

def decode_message(raw: Any) -> Any:
    """
    Decode one broker message for the alert pipeline.

    Returns a JSON value (dict / list) for JSON messages, the stripped text for
    an MMT-Probe CSV security report, and None for messages to skip: empty
    messages and non-alert MMT-Probe reports (e.g. the type-1 version report,
    in CSV or JSON form). Raises ValueError for anything else that is not JSON.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode('utf-8', errors='replace')
    text = (raw or '').strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        value = None
        report_type = _csv_report_type(text)
        if report_type == SECURITY_REPORT:
            return text
        if report_type is not None:
            return None            # other MMT-Probe report: not an alert
        raise ValueError('message is neither JSON nor an MMT-Probe CSV report')
    if _is_probe_list(value) and value[0] != SECURITY_REPORT:
        return None                # JSON-mode non-alert report
    return value


def _csv_report_type(text: str) -> Optional[int]:
    head = text.split(',', 2)
    if len(head) < 3:
        return None
    try:
        return int(head[0]) if int(head[1]) >= 0 else None
    except ValueError:
        return None


def _is_probe_list(value: Any) -> bool:
    return (isinstance(value, list) and len(value) >= 4
            and isinstance(value[0], int) and not isinstance(value[0], bool)
            and isinstance(value[1], int))


# ---------------------------------------------------------------------------
# Field extraction per shape
# ---------------------------------------------------------------------------

def _split_csv(text: str) -> Optional[List[Any]]:
    """CSV security report -> the same list the JSON mode emits."""
    brace = text.find('{')
    head, trace_txt = (text[:brace], text[brace:]) if brace >= 0 else (text, '')
    head = head.rstrip().rstrip(',')
    try:
        fields = next(csv.reader(io.StringIO(head)))
    except (StopIteration, csv.Error):
        return None
    if len(fields) < 8:
        return None
    try:
        trace = json.loads(trace_txt) if trace_txt else {}
    except (json.JSONDecodeError, ValueError):
        trace = {}
    out: List[Any] = [_num(fields[0]), _num(fields[1]), fields[2], _num(fields[3]),
                      _num(fields[4]), fields[5], fields[6], fields[7], trace]
    return out


def _num(s: Any) -> Any:
    if isinstance(s, (int, float)):
        return s
    try:
        f = float(s)
        return int(f) if f.is_integer() and '.' not in str(s) else f
    except (TypeError, ValueError):
        return s


def _attributes(trace: Any) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    if not isinstance(trace, dict):
        return out
    for key in sorted(trace, key=lambda k: (len(k), k)):     # event_1, event_2, ...
        ev = trace.get(key)
        for kv in (ev or {}).get('attributes', []) if isinstance(ev, dict) else []:
            if isinstance(kv, (list, tuple)) and len(kv) == 2:
                out.append((str(kv[0]), kv[1]))
    return out


def _first(attrs: List[Tuple[str, Any]], *names: str) -> str:
    for name in names:
        for k, v in attrs:
            if k == name and v not in (None, ''):
                return str(v)
    return ''


def _from_probe_list(fields: List[Any]) -> Dict[str, Any]:
    fields = list(fields) + [None] * (9 - len(fields))
    _, probe_id, source, ts, rule_id, verdict, rtype, desc, trace = fields[:9]
    attrs = _attributes(trace)
    macs = sorted({str(v) for k, v in attrs
                   if k in ('arp.ar_sha', 'ethernet.src') and v})
    return {
        'probe_id':    probe_id,
        'source':      source or '',
        'timestamp':   ts,
        'rule_id':     rule_id,
        'verdict':     verdict or '',
        'type':        rtype or '',
        'description': desc or '',
        # ARP rules carry no ip.*: use the contested IP from the ARP sender field.
        'srcip':       _first(attrs, 'ip.src', 'ipv6.src', 'arp.ar_sip'),
        'dstip':       _first(attrs, 'ip.dst', 'ipv6.dst'),
        'macs':        macs,
        'trace':       trace if isinstance(trace, dict) else {},
        'priority':    '',          # STIX only (mmt-probe#24)
    }


def _is_mmt_stix(alert: Any) -> bool:
    if not (isinstance(alert, dict) and alert.get('type') == 'bundle'):
        return False
    for obj in alert.get('objects') or []:
        if isinstance(obj, dict) and obj.get('type') == 'x-attack-type':
            refs = obj.get('external_references') or []
            if any(isinstance(r, dict) and r.get('source_name') == 'mmt-security'
                   for r in refs):
                return True
    return False


def _from_stix(bundle: Dict[str, Any]) -> Dict[str, Any]:
    objs = [o for o in bundle.get('objects') or [] if isinstance(o, dict)]
    by_id = {o.get('id'): o for o in objs}
    ident = next((o for o in objs if o.get('type') == 'identity'), {})
    obs = next((o for o in objs if o.get('type') == 'observed-data'), {})
    atk = next((o for o in objs if o.get('type') == 'x-attack-type'), {})
    ext = (ident.get('extensions') or {}).get('x-probe-id-ext') or {}
    rule_id = next((r.get('external_id') for r in atk.get('external_references') or []
                    if isinstance(r, dict) and r.get('source_name') == 'mmt-security'), '')
    refs = [by_id.get(r) or {} for r in obs.get('object_refs') or []]
    ips = [o.get('value', '') for o in refs if o.get('type') in ('ipv4-addr', 'ipv6-addr')]
    macs = sorted({o.get('value', '') for o in refs if o.get('type') == 'mac-addr'} - {''})
    props = (atk.get('extensions') or {}).get('x-attack-type-ext') or {}
    if not isinstance(props, dict):
        props = {}
    desc = (((obs.get('extensions') or {}).get('x-observed-data-ext') or {})
            .get('description') or atk.get('name') or '')
    return {
        'probe_id':    ext.get('probe-id', 0),
        'source':      ext.get('input-source', ''),
        'timestamp':   _iso_to_unix(obs.get('first_observed') or obs.get('created')),
        'rule_id':     _num(rule_id),
        'verdict':     _str(props.get('verdict')) or _STIX_DEFAULT_VERDICT,
        'type':        _str(props.get('rule_type')) or _STIX_DEFAULT_TYPE,
        'description': desc,
        # Probe order: source address first, destination second (one IP for ARP).
        'srcip':       ips[0] if ips else '',
        'dstip':       ips[1] if len(ips) > 1 else '',
        'macs':        macs,
        'trace':       {},
        'priority':    _priority(props.get('priority')),
        'stix_bundle_id': _str(bundle.get('id')),
    }


def _str(v: Any) -> str:
    return v.strip() if isinstance(v, str) else ''


def _alert_id(f: Dict[str, Any]) -> str:
    base = f"mmt-{f['probe_id']}-{f['timestamp']}-{f['rule_id']}"
    bundle_id = f.get('stix_bundle_id')
    if bundle_id:
        # STIX: ms timestamps; the bundle UUID keeps same-ms alerts of one rule apart
        return f"{base}-{bundle_id.split('--', 1)[-1]}"
    return base


def _iso_to_unix(s: Any) -> Any:
    if not isinstance(s, str):
        return 0
    try:
        return datetime.strptime(s.replace('Z', '+0000'), '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    except ValueError:
        try:
            return datetime.strptime(s.replace('Z', '+0000'), '%Y-%m-%dT%H:%M:%S%z').timestamp()
        except ValueError:
            return 0


def _unix_to_iso(ts: Any) -> str:
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'
    except (TypeError, ValueError, OverflowError, OSError):
        return str(ts)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class MMTProbeAdapter(AlertAdapter):
    """Native mmt-probe security reports: CSV text, JSON array, STIX 2.1 bundle."""

    @property
    def name(self) -> str:
        return "mmt"

    def can_handle(self, alert: Any) -> bool:
        if isinstance(alert, str):
            return _csv_report_type(alert.strip()) == SECURITY_REPORT
        if _is_probe_list(alert):
            return alert[0] == SECURITY_REPORT and len(alert) >= 8
        return _is_mmt_stix(alert)

    def normalize(self, alert: Any) -> Dict[str, Any]:
        if isinstance(alert, str):
            fmt, f = 'csv', _from_probe_list(_split_csv(alert.strip()) or [SECURITY_REPORT])
        elif isinstance(alert, list):
            fmt, f = 'json', _from_probe_list(alert)
        else:
            fmt, f = 'stix', _from_stix(alert)

        rtype = str(f['type'])
        probe_id = f['probe_id']
        return {
            "_index":  "mmt-alerts",
            "_id":     _alert_id(f),
            "_source": {
                "timestamp": _unix_to_iso(f['timestamp']),
                "observer": {
                    "id":   str(probe_id),
                    "name": f"mmt-probe-{probe_id}",
                    "type": "ids",
                },
                "rule": {
                    "id":          str(f['rule_id']),
                    "level":       _level(f['priority'], rtype),
                    "description": f['description'],
                    "groups":      [g for g in (rtype, f['verdict'], 'security') if g],
                    "mitre":       {},   # no T-codes in MMT rules — Path B/C infer
                },
                "data": {
                    "srcip":    f['srcip'],
                    "dstip":    f['dstip'],
                    "macs":     f['macs'],
                    "category": rtype,
                    "status":   f['verdict'],
                    "priority": f['priority'],
                    "code":     f['rule_id'],
                    "probe_id": probe_id,
                    "input_source": f['source'],
                    "mmt_format":   fmt,
                    "event_trace":  f['trace'],
                    **({"stix_bundle_id": f['stix_bundle_id']} if 'stix_bundle_id' in f else {}),
                },
            },
            "_adapter": self.name,
            "_raw":     alert,
        }

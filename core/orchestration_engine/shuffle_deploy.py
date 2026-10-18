"""
Deploy a (parameterized) CACAO playbook to Shuffle as a workflow, so it can be opened
and run there.

The playbook is converted with core/playbook_generation/cacao_to_shuffle.py and created
in Shuffle under a name that ends with a tag derived from the converted content: the same
playbook for the same alert maps to the same workflow, which is reused instead of piling
up copies; any change (other alert values, other mode) gives a new tag and a new workflow.
"""

import copy
import hashlib
import json
import logging
import os
import re
import time
from typing import Dict, Optional

import requests

from core.config import config
from core.playbook_generation.cacao_to_shuffle import ConversionError, convert, fetch_app_catalog

logger = logging.getLogger(__name__)

_CATALOG_TTL = 600            # seconds: app ids rarely change; one /apps call per 10 min
_catalog_cache: Dict = {"at": 0.0, "catalog": None}


def _live_catalog():
    if _catalog_cache["catalog"] is None or time.time() - _catalog_cache["at"] > _CATALOG_TTL:
        _catalog_cache["catalog"] = fetch_app_catalog(config.shuffle)
        _catalog_cache["at"] = time.time()
    return _catalog_cache["catalog"]


def _api(method: str, path: str, **kwargs) -> requests.Response:
    s = config.shuffle
    resp = requests.request(method, f"{s.api_base_url}{path}",
                            headers={**s.get_headers(), "Content-Type": "application/json"},
                            timeout=30, **kwargs)
    resp.raise_for_status()
    return resp


MODES = ("shuffle", "dry_run")


def demo_victim() -> Optional[Dict[str, str]]:
    """The demo victim (docker-compose.lab.yml) from .env, or None when not set up."""
    host = os.getenv("DEMO_VICTIM_HOST", "").strip()
    if not host:
        return None
    return {"host": host, "port": os.getenv("DEMO_VICTIM_PORT", "22"),
            "user_name": os.getenv("DEMO_VICTIM_USER", "root"),
            "password": os.getenv("DEMO_VICTIM_PASSWORD", ""), "name": "web-01"}


# Demo lab: what the alert does not say, as it exists on the demo victim (web-01), so a
# playbook from any alert has something to act on. Shown in the Execute dialog.
LAB_VALUES = {
    "hostname": "web-01", "username": "alice", "process_name": "/tmp/payload.sh",
    "file_path": "/tmp/payload.sh", "src_ip": "203.0.113.66", "dst_ip": "198.51.100.23",
    "disputed_ip": "192.0.2.1", "dst_port": "22", "duration_hours": "24", "protocol": "ssh",
    "url": "http://198.51.100.23/login", "email_sender": "invoice@phish.example",
    "email_subject": "Invoice overdue", "mail_server": "web-01",
}


def _fill_lab_values(cacao: Dict) -> tuple:
    """The playbook with every parameter the alert left open ({{name}}, or UNKNOWN_NAME
    for a required one) set to its demo lab value; and {name: value} of those used."""
    text, used = json.dumps(cacao), {}
    for name, value in LAB_VALUES.items():
        pattern = r"\{\{\s*" + re.escape(name) + r"\s*\}\}|\bUNKNOWN_" + re.escape(name.upper()) + r"\b"
        if re.search(pattern, text):
            text = re.sub(pattern, value, text)
            used[name] = value
    return json.loads(text), used


def _use_demo_victim(workflow: Dict, warnings: list, victim: Dict[str, str]) -> None:
    """Demo lab: every Run ssh command node acts on the demo victim, whatever host the
    alert named (a name from an alert does not resolve in the lab) and with its login.
    The host and credentials warnings no longer apply."""
    for a in workflow["actions"]:
        if a.get("name") != "run_ssh_command":
            continue
        for p in a["parameters"]:
            if p["name"] in ("host", "port", "user_name", "password"):
                p["value"] = victim[p["name"]]
            elif p["name"] == "private_key_file_id":
                p["value"] = ""
    warnings[:] = [w for w in warnings
                   if "SSH credentials" not in w and "affected host" not in w and "no ssh host" not in w]


def _name_unknown_host(cacao: Dict) -> Dict:
    """Step names (the node labels) say "affected host" where the alert gave no hostname."""
    cacao = copy.deepcopy(cacao)
    for step in (cacao.get("workflow") or {}).values():
        if step.get("name"):
            step["name"] = re.sub(r"UNKNOWN_HOSTNAME|\{\{\s*hostname\s*\}\}", "affected host", step["name"])
    return cacao


def _blank_unknown_hosts(workflow: Dict, warnings: list) -> None:
    """A per-alert workflow whose alert does not name the affected host: leave the Run ssh
    command host empty for the operator (an unfilled parameter would otherwise show up as
    $exec.hostname or UNKNOWN_HOSTNAME)."""
    blanked = []
    for a in workflow["actions"]:
        if a.get("name") != "run_ssh_command":
            continue
        for p in a["parameters"]:
            if p["name"] == "host" and (p.get("value", "").startswith("$exec.")
                                        or p.get("value", "").startswith("UNKNOWN_")):
                p["value"] = ""
                blanked.append(a["label"])
    if blanked:
        warnings.insert(0, "The affected host is not in the alert: fill Host on the Run ssh command "
                           f"node(s) in Shuffle ({', '.join(blanked)})")


def deploy_playbook(cacao: Dict, generated: bool = False) -> Dict:
    """Create (or reuse) the Shuffle workflow for this playbook.

    Mode from SHUFFLE_EXECUTION_MODE (see ShuffleConfig): "shuffle" builds the nodes as
    by hand in the editor (Run ssh command on the victim, credentials left for the
    operator to fill), "dry_run" only echoes. generated is kept for callers (Path D).
    Returns {workflow_id, name, url, mode, reused, warnings, nodes}.
    Raises ValueError for a configuration problem, ConversionError if the playbook
    cannot be expressed as a Shuffle workflow.
    """
    s = config.shuffle
    mode = s.execution_mode
    if mode not in MODES:
        raise ValueError(f"SHUFFLE_EXECUTION_MODE must be one of {', '.join(MODES)}, not '{mode}'")

    from core.intelligent_orchestration.parameterizer import fill_secrets
    victim = demo_victim() if mode != "dry_run" else None
    lab_values = {}
    if victim:   # before the names: a step reads "on web-01", not "on affected host"
        cacao, lab_values = _fill_lab_values(cacao)
    cacao = fill_secrets(_name_unknown_host(cacao))       # API keys: in Shuffle only
    workflow, warnings = convert(cacao, _live_catalog(), dry_run=mode == "dry_run")
    if victim:
        _use_demo_victim(workflow, warnings, victim)
    else:
        _blank_unknown_hosts(workflow, warnings)
    # The tag follows the final nodes (after the host / demo-victim adjustments above), so
    # a workflow changed by them is never mistaken for an older one of the same playbook
    tag = hashlib.sha1(json.dumps([workflow["actions"], workflow["branches"]],
                                  sort_keys=True).encode()).hexdigest()[:8]
    name = f"{cacao.get('name', 'AI4SOAR playbook')} · AI4SOAR {tag}" + \
           (" (dry run)" if mode == "dry_run" else "")

    existing = next((w for w in _api("GET", "/workflows").json() or []
                     if w.get("name") == name), None)
    if existing:
        wid, reused = existing["id"], True
    else:
        created = _api("POST", "/workflows",
                       json={"name": name, "description": workflow.get("description", "")}).json()
        wid, reused = created["id"], False
        body = {**created, "id": wid, "name": name,
                **{k: workflow[k] for k in ("actions", "branches", "start", "triggers",
                                            "configuration", "description", "tags")}}
        saved = _api("PUT", f"/workflows/{wid}", json=body).json()
        if not saved.get("success", True):
            raise ValueError(f"Shuffle refused the workflow: {saved.get('errors') or saved}")
        logger.info(f"[Shuffle deploy] created workflow {wid} '{name}' ({mode}, "
                    f"{len(workflow['actions'])} nodes, {len(warnings)} warnings)")

    return {
        "workflow_id": wid,
        "name": name,
        "url": s.workflow_url(wid),
        "mode": mode,
        "reused": reused,
        "nodes": len(workflow["actions"]),
        "warnings": warnings,
        # demo lab: the SSH steps act on this machine (shown in the Execute dialog)
        "demo_victim": ({"name": victim["name"], "address": f"{victim['host']}:{victim['port']}",
                         "lab_values": lab_values}
                        if victim and any(a.get("name") == "run_ssh_command" for a in workflow["actions"])
                        else None),
    }


__all__ = ["deploy_playbook", "ConversionError"]

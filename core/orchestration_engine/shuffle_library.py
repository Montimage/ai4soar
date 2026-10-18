"""
Keep the CACAO playbook library (playbooks/*.yaml) in Shuffle as reusable workflows, one
per template, named "AI4SOAR library · <template name>".

Each workflow is the template itself, not filled for one alert: every {{parameter}}
becomes $exec.<parameter>, Shuffle's execution argument; the example argument holds sample
values. Deployment settings (parameters with env:, like INCIDENT_API_URL) are filled from
the environment when set.

sync() creates the missing workflows and updates those whose converted content changed,
detected by a fingerprint kept in the workflow description; values the operator entered
in Shuffle (SSH credentials) are kept. Node ids derive from the template's step ids, so a
step keeps its node across updates.
"""

import glob
import json
import os
import re
from typing import Dict, List, Optional

import yaml

from core.config import config
from core.intelligent_orchestration.parameterizer import template_labels
from core.orchestration_engine.shuffle_deploy import _api, _live_catalog
from core.playbook_generation.cacao_to_shuffle import convert

PREFIX = "AI4SOAR library · "
PLAYBOOK_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "playbooks")
_FINGERPRINT = re.compile(r"\[ai4soar-fingerprint:([0-9a-f]{8})\]")

# Filled by the operator in Shuffle, never by the converter: kept when a workflow is updated
OPERATOR_FIELDS = ("user_name", "password", "private_key_file_id", "port")

# Sample values for the example execution argument, by parameter name
SAMPLES = {
    "src_ip": "192.168.0.59", "dst_ip": "192.168.0.101", "disputed_ip": "192.168.0.1",
    "hostname": "", "username": "alice", "dst_port": "22", "duration_hours": "24",
    "process_name": "/tmp/payload.sh", "file_path": "/var/tmp/stage/archive.zip",
    "email_sender": "invoice@phish.example", "email_subject": "Invoice Q3 overdue",
    "url": "https://shop.example/login", "protocol": "ssh", "mail_server": "mail.example",
}


def templates(only: Optional[List[str]] = None) -> List[Dict]:
    """The library templates, optionally only those whose file name or id contains a term."""
    out = []
    for path in sorted(glob.glob(os.path.join(PLAYBOOK_DIR, "*.yaml"))):
        with open(path) as fh:
            t = yaml.safe_load(fh)
        t["_file"] = os.path.basename(path)
        if not only or any(o in t["_file"] or o == t.get("id") for o in only):
            out.append(t)
    return out


def _template_cacao(t: Dict) -> Dict:
    text = json.dumps(t["cacao"])
    for name, spec in (t.get("parameters") or {}).items():
        if spec.get("env") and os.getenv(spec["env"]):
            text = re.sub(r"\{\{\s*" + name + r"\s*\}\}", os.environ[spec["env"]], text)
    cacao = json.loads(text)
    cacao["name"] = PREFIX + t["name"]
    cacao["labels"] = template_labels(t)
    return cacao


def example_argument(t: Dict) -> Dict[str, str]:
    return {name: str(SAMPLES.get(name, spec.get("default", f"<{name}>")))
            for name, spec in (t.get("parameters") or {}).items() if not spec.get("env")}


def _keep_operator_values(new_actions: List[Dict], old_actions: List[Dict]) -> int:
    old = {a["id"]: {p["name"]: p.get("value") for p in a.get("parameters") or []}
           for a in old_actions or []}
    kept = 0
    for a in new_actions:
        before = old.get(a["id"]) or {}
        for p in a["parameters"]:
            if p["name"] in OPERATOR_FIELDS and not p.get("value") and before.get(p["name"]):
                p["value"] = before[p["name"]]
                kept += 1
    return kept


def _build(t: Dict, catalog) -> Dict:
    cacao = _template_cacao(t)
    workflow, warnings = convert(cacao, catalog)
    fingerprint = workflow["id"][:8]          # derived from the converted content
    argument = example_argument(t)
    description = (f"{t.get('description', '')}\n\nAI4SOAR library template {t['id']} "
                   f"({', '.join(t.get('techniques') or [])}). Every $exec.<name> is a template "
                   f"parameter: run it with an execution argument, e.g.\n{json.dumps(argument)}\n"
                   f"[ai4soar-fingerprint:{fingerprint}]")
    return {"name": cacao["name"], "workflow": workflow, "warnings": warnings,
            "fingerprint": fingerprint, "description": description, "argument": argument}


def _tags_match(existing: Dict, built: Dict) -> bool:
    return sorted(existing.get("tags") or []) == sorted(built["workflow"]["tags"])


def status(only: Optional[List[str]] = None) -> List[Dict]:
    """Per template: in Shuffle or not, and whether its workflow matches the template."""
    existing = {w["name"]: w for w in _api("GET", "/workflows").json() or []}
    catalog = _live_catalog()
    out = []
    for t in templates(only):
        built = _build(t, catalog)
        w = existing.get(built["name"])
        m = _FINGERPRINT.search((w or {}).get("description") or "")
        state = ("missing" if not w else
                 "current" if m and m.group(1) == built["fingerprint"] and _tags_match(w, built) else
                 "outdated")
        out.append({"template_id": t["id"], "file": t["_file"], "name": built["name"],
                    "state": state, "workflow_id": (w or {}).get("id"),
                    "url": config.shuffle.workflow_url(w["id"]) if w else None,
                    "warnings": built["warnings"]})
    return out


def sync(only: Optional[List[str]] = None, force: bool = False) -> List[Dict]:
    """Create missing library workflows and update outdated ones (all if force)."""
    existing = {w["name"]: w for w in _api("GET", "/workflows").json() or []}
    catalog = _live_catalog()
    results = []
    for t in templates(only):
        built = _build(t, catalog)
        workflow, name = built["workflow"], built["name"]
        w = existing.get(name)
        m = _FINGERPRINT.search((w or {}).get("description") or "")
        if w and m and m.group(1) == built["fingerprint"] and _tags_match(w, built) and not force:
            results.append({"template_id": t["id"], "file": t["_file"], "name": name, "action": "unchanged",
                            "workflow_id": w["id"], "url": config.shuffle.workflow_url(w["id"]), "ok": True,
                            "kept": 0, "warnings": built["warnings"]})
            continue
        kept = 0
        if w:
            wid, action = w["id"], "updated"
            base = _api("GET", f"/workflows/{wid}").json()
            kept = _keep_operator_values(workflow["actions"], base.get("actions"))
        else:
            base = _api("POST", "/workflows", json={"name": name, "description": built["description"]}).json()
            wid, action = base["id"], "created"
        body = {**base, "id": wid, "name": name, "description": built["description"],
                "example_argument": json.dumps(built["argument"]),
                **{k: workflow[k] for k in ("actions", "branches", "start", "triggers", "configuration",
                                            "tags")}}
        saved = _api("PUT", f"/workflows/{wid}", json=body).json()
        back = _api("GET", f"/workflows/{wid}").json()
        ok = bool(saved.get("success", True)
                  and len(back.get("actions") or []) == len(workflow["actions"])
                  and len(back.get("branches") or []) == len(workflow["branches"])
                  and back.get("start") == workflow["start"])
        results.append({"template_id": t["id"], "file": t["_file"], "name": name, "action": action,
                        "workflow_id": wid, "url": config.shuffle.workflow_url(wid), "ok": ok,
                        "kept": kept, "warnings": built["warnings"],
                        "error": None if ok else str(saved.get("errors") or saved)})
    return results


def delete_all() -> List[str]:
    deleted = []
    for w in _api("GET", "/workflows").json() or []:
        if w.get("name", "").startswith(PREFIX):
            _api("DELETE", f"/workflows/{w['id']}")
            deleted.append(w["name"])
    return deleted

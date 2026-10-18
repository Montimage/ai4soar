"""
Dry-run CACAO playbooks on SOARCA (github.com/COSSAS/SOARCA), the open-source CACAO 2.0
orchestrator by TNO, running as an external container (docker-compose.soarca.yml).

SOARCA executes CACAO natively but with its own conventions (SOARCA-PLAYBOOK-GRAMMAR-
CACAO-V2.md in its repository): commands run through its agents (soarca-ssh,
soarca-http-api) against targets with hard-coded addresses (ipv4 only for ssh) and
credentials, `on_completion` is the flow (on_failure is not followed, a failing step
aborts the run), and step ids must be UUIDv4.

A dry run keeps the playbook's flow and step names and replaces every step by one
soarca-ssh command on the sandbox host that prints what the step would do: the commands
for its target machine, or the HTTP request it would send. Nothing real is touched, and
the SOARCA execution report shows each step run in order.
"""

import base64
import copy
import re
import uuid
from typing import Dict, List, Tuple

import requests

from core.config import config

_NS = uuid.UUID("5b3f8e2a-6c1d-4f7e-9a0b-2c4d6e8f0a1b")
_FLOW = ("on_completion", "on_success", "on_failure", "on_true", "on_false")


class SoarcaError(RuntimeError):
    pass


def _api(method: str, path: str, **kwargs) -> requests.Response:
    s = config.soarca
    if not s.url:
        raise SoarcaError("SOARCA_URL is not set")
    try:
        r = requests.request(method, f"{s.url}{path}", timeout=15, **kwargs)
    except requests.RequestException as e:
        raise SoarcaError(f"SOARCA unreachable at {s.url}: {e}")
    if r.status_code >= 400:
        raise SoarcaError(f"SOARCA {method} {path}: HTTP {r.status_code} {r.text[:300]}")
    return r


def status() -> Dict:
    """Version and uptime from GET /status/ (health check)."""
    return _api("GET", "/status/").json()


def _text(cmd: Dict, key: str) -> str:
    if cmd.get(key) is not None:
        return str(cmd[key])
    if cmd.get(f"{key}_b64"):
        try:
            return base64.b64decode(cmd[f"{key}_b64"]).decode("utf-8", "replace")
        except ValueError:
            return ""
    return ""


def _where(cacao: Dict, step: Dict) -> str:
    targets = cacao.get("target_definitions") or {}
    names = [(targets.get(t) or {}).get("name") or t for t in step.get("targets") or []]
    if names:
        return ", ".join(names)
    agent = (cacao.get("agent_definitions") or {}).get(step.get("agent")) or {}
    return agent.get("name") or step.get("agent") or "the playbook runner"


def _describe(cacao: Dict, step: Dict) -> str:
    """What the step would do, as the text the sandbox prints."""
    lines = [f"[dry run] {step.get('name') or 'step'}"]
    agent = (cacao.get("agent_definitions") or {}).get(step.get("agent")) or {}
    for cmd in step.get("commands") or []:
        ctype = cmd.get("type") or "bash"
        body = _text(cmd, "command")
        if ctype in ("http-api", "openc2-http"):
            url = ((agent.get("address") or {}).get("url") or [""])[0]
            method, _, rest = body.partition(" ")
            lines.append(f"would send to {url or '(no URL)'}: {method} {rest.split(' ')[0]}")
            content = _text(cmd, "content")
            if content:
                lines.append(content.strip())
        elif ctype == "manual":
            lines.append(f"message for the operator: {body}")
        else:
            lines.append(f"would run on {_where(cacao, step)} ({ctype}):")
            lines += [f"  $ {ln}" for ln in body.strip().splitlines() if ln.strip()]
    if step.get("type") == "if-condition":
        lines.append(f"would check {step.get('condition', '')}: the dry run goes on with the "
                     f"'true' branch")
    elif step.get("type") not in (None, "action"):
        lines.append(f"{step['type']} {step.get('condition') or ''}: the dry run follows its "
                     f"first branch")
    # CACAO variables only get a value in a real run: show them as <name>
    return re.sub(r"__(\w+?)__:value", r"<\1>", "\n".join(lines)) + "\n"


def to_dry_run(cacao: Dict) -> Tuple[Dict, List[str], List[Dict]]:
    """The playbook in SOARCA's dialect, every step printing what it would do on the sandbox."""
    s = config.soarca
    if not s.sandbox_password:
        raise SoarcaError("SOARCA_SANDBOX_PASSWORD is not set")
    wf = cacao.get("workflow") or {}
    warnings: List[str] = []
    # Fresh UUIDv4 step ids (SOARCA requires v4; parameterized templates use v5)
    kind = lambda st: (st or {}).get("type") if (st or {}).get("type") in ("start", "end") else "action"
    ids = {sid: f"{kind(st)}--{uuid.uuid4()}" for sid, st in wf.items()}
    agent = f"soarca--{uuid.uuid5(_NS, 'soarca-ssh')}"
    target = f"ssh--{uuid.uuid5(_NS, 'sandbox')}"
    auth = f"user-auth--{uuid.uuid5(_NS, 'sandbox-auth')}"

    out = {}
    for sid, st in wf.items():
        st = st or {}
        stype = st.get("type", "action")
        nxt = next((st[k] for k in _FLOW if st.get(k)), None) \
            or next(iter(st.get("next_steps") or []), None) \
            or next(iter((st.get("cases") or {}).values()), None)
        if stype == "end":
            out[ids[sid]] = {"type": "end", "name": st.get("name", "End")}
            continue
        if stype == "start":
            out[ids[sid]] = {"type": "start", "name": st.get("name", "Start"),
                             "on_completion": ids.get(nxt)}
            continue
        if st.get("on_failure") and st.get("on_failure") != nxt:
            warnings.append(f"'{st.get('name') or sid}': SOARCA does not follow on_failure "
                            f"(a failing step stops the run); the dry run follows on_success")
        script = base64.b64encode(_describe(cacao, st).encode()).decode()
        out[ids[sid]] = {
            "type": "action",
            "name": st.get("name") or sid,
            "description": st.get("description", ""),
            "agent": agent,
            "targets": [target],
            # base64 keeps quoting intact (and SOARCA cuts commands at the text "ssh ")
            "commands": [{"type": "ssh", "command": f"echo {script} | base64 -d"}],
            "out_args": ["__soarca_ssh_result__"],
            "on_completion": ids.get(nxt),
        }
        if not nxt:
            warnings.append(f"'{st.get('name') or sid}' has no next step")

    # Steps the dry run does not reach (the other branch of a condition), for the report
    reached, todo = set(), [cacao.get("workflow_start")]
    while todo:
        sid = todo.pop()
        if sid in reached or sid not in wf:
            continue
        reached.add(sid)
        st = wf[sid] or {}
        todo.append(next((st[k] for k in _FLOW if st.get(k)), None)
                    or next(iter(st.get("next_steps") or []), None)
                    or next(iter((st.get("cases") or {}).values()), None))
    skipped = []
    for sid, st in wf.items():
        st = st or {}
        if sid in reached or st.get("type") in ("start", "end"):
            continue
        parent = next((p for p in wf.values() if p and sid in (p.get("on_false"), *(p.get("cases") or {}).values(),
                                                                 *(p.get("next_steps") or []))), None)
        skipped.append({"name": st.get("name") or sid, "after": (parent or {}).get("name"),
                        "reason": (f"the dry run follows the 'true' branch of '{parent.get('name')}'"
                                   if parent else "not reached in the dry run")})

    pb = {k: copy.deepcopy(v) for k, v in cacao.items()
          if k in ("type", "spec_version", "description", "created_by", "created", "modified",
                   "playbook_types", "labels")}
    pb.update({
        "type": "playbook", "spec_version": "cacao-2.0",
        "id": f"playbook--{uuid.uuid4()}",
        "name": f"[AI4SOAR dry run] {cacao.get('name', 'playbook')}",
        "created_by": cacao.get("created_by") or "identity--c8bde83a-ff38-57ad-bec8-7f3775beb1e4",
        "created": cacao.get("created") or "2026-01-01T00:00:00Z",
        "modified": cacao.get("modified") or "2026-01-01T00:00:00Z",
        "agent_definitions": {agent: {"type": "soarca", "name": "soarca-ssh"}},
        "target_definitions": {target: {"type": "ssh", "name": "AI4SOAR dry-run sandbox",
                                        "address": {"ipv4": [s.sandbox_host]}, "port": "22",
                                        "authentication_info": auth}},
        "authentication_info_definitions": {auth: {"type": "user-auth", "username": s.sandbox_user,
                                                   "password": s.sandbox_password}},
        "workflow_start": ids.get(cacao.get("workflow_start")),
        "workflow": out,
    })
    return pb, warnings, skipped


def _fill_plain(cacao: Dict) -> Dict:
    """.env settings that are not secrets (an API key never goes to the dry run)."""
    import json, os
    from core.intelligent_orchestration.parameterizer import secret_settings
    secret = secret_settings()
    text = json.dumps(cacao)
    for name, env in secret_settings(include_plain=True).items():
        if name not in secret and os.getenv(env):
            text = re.sub(r"\{\{\s*" + re.escape(name) + r"\s*\}\}",
                          lambda _m: json.dumps(os.environ[env])[1:-1], text)
    return json.loads(text)


def run_dry(cacao: Dict) -> Dict:
    """Trigger the dry run. Returns {execution_id, warnings, steps, skipped}: steps counts
    every step of the playbook, skipped lists those on a branch the dry run does not take."""
    pb, warnings, skipped = to_dry_run(_fill_plain(cacao))
    r = _api("POST", "/trigger/playbook", json=pb).json()
    return {"execution_id": r.get("execution_id"), "warnings": warnings, "skipped": skipped,
            "steps": sum(1 for s in pb["workflow"].values() if s["type"] == "action")}


def results(execution_id: str) -> Dict:
    """The execution report: overall status and each step in the order it ran."""
    rep = _api("GET", f"/reporter/{execution_id}").json()
    steps = []
    for st in sorted((rep.get("step_results") or {}).values(), key=lambda x: x.get("started") or ""):
        out = ((st.get("variables") or {}).get("__soarca_ssh_result__") or {}).get("value", "")
        steps.append({"name": st.get("name"), "status": st.get("status"),
                      "output": out, "error": "" if st.get("status") == "successfully_executed"
                      else st.get("status_text", "")})
    return {"status": rep.get("status"), "status_text": rep.get("status_text", ""),
            "started": rep.get("started"), "ended": rep.get("ended"), "steps": steps,
            "raw": rep}     # SOARCA's execution report as is (View / Copy JSON)

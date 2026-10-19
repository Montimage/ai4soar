"""
OASIS CACAO 2.0 playbook generator.

Used by Path D when no pre-existing playbooks can be matched with sufficient
confidence. Generates a structured incident-response playbook with
machine-readable bash/HTTP-API steps.

The generator pre-assigns all step UUIDs in the skeleton so the LLM cannot
break cross-step references — it only fills in names, descriptions, and commands.

IMPORTANT: Always set review_required / confidence_tier=LOW before executing
any generated playbook. LLMs can hallucinate commands.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict

from core.config import config
from core.exceptions import LLMUnavailableError
from core.intelligent_orchestration.parameterizer import AI4SOAR_IDENTITY
from utils.llm.client import call_llm, strip_fences

# The same agent as the library templates (playbooks/*.yaml): the system that runs the
# steps. Each step acts over SSH on its target, the affected host.
RUNNER_AGENT_ID = "linux--3a7f9c1e-5b2d-4c8a-9e6f-7d1b2c3e4f50"
RUNNER_AGENT = {
    "type": "linux",
    "name": "AI4SOAR / Shuffle",
    "description": "Runs the steps; each one acts over SSH on its target machine",
    "address": {"ipv4": ["127.0.0.1"]},
}

logger = logging.getLogger(__name__)


def generate(alert_text: str) -> Dict:
    """
    Generate a CACAO 2.0 playbook for the given alert description.

    Args:
        alert_text: Human-readable alert summary (from llm.client.alert_to_text).

    Returns:
        Parsed CACAO 2.0 dict with a complete workflow.

    Raises:
        LLMUnavailableError: if no LLM API key is configured.
        json.JSONDecodeError: if the LLM returns malformed JSON.
    """
    skeleton = _build_skeleton()
    prompt = (
        "You are a cybersecurity incident response expert.\n"
        "Generate a CACAO 2.0 security playbook for the alert below.\n\n"
        f"Alert:\n{alert_text}\n\n"
        "Fill in the skeleton. Replace every <fill: …> placeholder with specific, "
        "actionable content. Keep ALL step IDs and top-level fields exactly as given. "
        "Use real bash commands. Every step runs over SSH ON the affected host (the target), "
        "as root: write the command itself, never an 'ssh <host> ...' wrapper. Firewall rules "
        "are that host's own: iptables INPUT for traffic to it, OUTPUT for traffic it sends.\n"
        "Keep every command simple enough for a junior SOC analyst to read at a glance: 1 to 3 "
        "short commands per step, one per line, each doing one obvious thing with a standard "
        "tool (ps, ss, kill, pkill, iptables, mv, rm, crontab, systemctl, usermod, tee). No "
        "shell variables, functions, loops, subshells, || / && fallback chains or long "
        "pipelines. A command that changes something and prints nothing on success "
        "(iptables, usermod, chmod, mv) is followed by one that shows the result (iptables -S, "
        "passwd -S, ls -l), so the output proves what was done.\n"
        "Return ONLY the completed JSON — no markdown fences, no explanation.\n\n"
        f"{json.dumps(skeleton, indent=2)}\n"
    )
    raw    = call_llm(prompt, max_tokens=config.llm.playbook_max_tokens)
    result = json.loads(strip_fences(raw))
    logger.info(f"[CACAO Generator] Generated playbook: {result.get('id')}")
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_skeleton() -> Dict:
    """
    Produce a CACAO 2.0 skeleton with pre-assigned identifiers ("<type>--<uuid>"), a start
    step, and the playbook-runner agent on every action, like the library templates; it
    validates against the official schema once the LLM has filled it in.
    The LLM fills in names, descriptions, and commands only.
    """
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pb_id     = f"playbook--{uuid.uuid4()}"
    s_start   = f"start--{uuid.uuid4()}"
    s_invest  = f"action--{uuid.uuid4()}"
    s_contain = f"action--{uuid.uuid4()}"
    s_recover = f"action--{uuid.uuid4()}"
    s_report  = f"action--{uuid.uuid4()}"
    s_end     = f"end--{uuid.uuid4()}"
    victim    = f"ssh--{uuid.uuid4()}"

    def action(name: str, description: str, command: str, nxt: str) -> Dict:
        return {"type": "action", "name": name, "description": description,
                "agent": RUNNER_AGENT_ID, "targets": [victim],
                "commands": [{"type": "bash", "command": command}],
                "on_completion": nxt}

    return {
        "type":           "playbook",
        "spec_version":   "cacao-2.0",
        "id":             pb_id,
        "name":           "<fill: descriptive playbook name>",
        "description":    "<fill: what this playbook does>",
        "labels":         ["<fill: MITRE ATT&CK technique id(s) of the alert, e.g. T1110, one per item>",
                           "<fill: ATT&CK tactic(s), e.g. credential-access>"],
        "created_by":     AI4SOAR_IDENTITY,
        "created":        now,
        "modified":       now,
        "agent_definitions": {RUNNER_AGENT_ID: RUNNER_AGENT},
        "target_definitions": {victim: {
            "type": "ssh",
            "name": "<fill: affected host name or IP, from the alert>",
            "description": "The machine the steps act on (the victim). In Shuffle, fill the "
                           "credentials of an account with root rights on it.",
            "address": {"dname": ["<fill: the same host name or IP>"]},
        }},
        "workflow_start": s_start,
        "workflow": {
            s_start:   {"type": "start", "on_completion": s_invest},
            s_invest:  action("Investigate", "<fill: what evidence to gather>",
                              "<fill: investigation command>", s_contain),
            s_contain: action("Contain", "<fill: how to isolate or block the threat>",
                              "<fill: containment command>", s_recover),
            s_recover: action("Recover", "<fill: how to restore normal operations>",
                              "<fill: recovery command>", s_report),
            s_report:  action("Document", "Record incident findings and lessons learned.",
                              "<fill: command that appends a one-line summary of the incident "
                              "and the actions taken to /var/log/ai4soar_incidents.log with tee -a, so the line also "
                              "shows in the step output>", s_end),
            s_end:     {"type": "end"},
        },
    }

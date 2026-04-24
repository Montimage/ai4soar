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
from utils.llm.client import call_llm, strip_fences

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
        "Use real bash commands or HTTP-API calls where appropriate.\n"
        "Return ONLY the completed JSON — no markdown fences, no explanation.\n\n"
        f"{json.dumps(skeleton, indent=2)}\n"
    )
    raw    = call_llm(prompt, max_tokens=config.llm.max_tokens)
    result = json.loads(strip_fences(raw))
    logger.info(f"[CACAO Generator] Generated playbook: {result.get('id')}")
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_skeleton() -> Dict:
    """
    Produce a CACAO 2.0 skeleton with pre-assigned UUIDs.
    The LLM fills in names, descriptions, and commands only.
    """
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pb_id     = f"playbook--{uuid.uuid4()}"
    s_invest  = f"step--{uuid.uuid4()}"
    s_contain = f"step--{uuid.uuid4()}"
    s_recover = f"step--{uuid.uuid4()}"
    s_report  = f"step--{uuid.uuid4()}"
    s_end     = f"step--{uuid.uuid4()}"

    return {
        "type":           "playbook",
        "spec_version":   "cacao-2.0",
        "id":             pb_id,
        "name":           "<fill: descriptive playbook name>",
        "description":    "<fill: what this playbook does>",
        "created":        now,
        "workflow_start": s_invest,
        "workflow": {
            s_invest: {
                "type":          "single",
                "name":          "Investigate",
                "description":   "<fill: what evidence to gather>",
                "commands":      [{"type": "bash", "command": "<fill: investigation command>"}],
                "on_completion": s_contain,
            },
            s_contain: {
                "type":          "single",
                "name":          "Contain",
                "description":   "<fill: how to isolate or block the threat>",
                "commands":      [{"type": "bash", "command": "<fill: containment command>"}],
                "on_completion": s_recover,
            },
            s_recover: {
                "type":          "single",
                "name":          "Recover",
                "description":   "<fill: how to restore normal operations>",
                "commands":      [{"type": "bash", "command": "<fill: recovery command>"}],
                "on_completion": s_report,
            },
            s_report: {
                "type":          "single",
                "name":          "Document",
                "description":   "Record incident findings and lessons learned.",
                "commands":      [],
                "on_completion": s_end,
            },
            s_end: {"type": "end"},
        },
    }

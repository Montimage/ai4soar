"""
Shared LLM client used by Path B (technique attribution) and Path D / playbook_generation.

Supports OpenAI, Anthropic and local Ollama; auto-detects OpenAI/Anthropic based on
available API keys. Ollama has no API key, so it must be selected explicitly via
LLM_PROVIDER=ollama. Swap providers or add a new one (Bedrock, …) only here.
"""

import json
import logging
from typing import Dict, List

from core.config import config
from core.exceptions import LLMUnavailableError

logger = logging.getLogger(__name__)


def alert_to_text(alert: Dict) -> str:
    """Flatten an alert dict to a concise human-readable string for LLM prompts."""
    src   = alert.get("_source", alert)
    rule  = src.get("rule", {})
    data  = src.get("data", {})
    agent = src.get("agent", {})

    parts: List[str] = []
    if agent.get("name"):
        parts.append(f"Host: {agent['name']}")
    if rule.get("description"):
        parts.append(f"Rule: {rule['description']}")
    if rule.get("groups"):
        parts.append(f"Groups: {', '.join(rule.get('groups', []))}")
    raw = data.get("raw_text") or data.get("message") or src.get("full_log", "")
    if raw:
        parts.append(f"Log: {str(raw)[:600]}")
    for key in ("srcip", "dstip", "src_process", "user", "event_type"):
        if data.get(key):
            parts.append(f"{key}: {data[key]}")

    return "\n".join(parts) if parts else json.dumps(src, default=str)[:1000]


def call_llm(prompt: str, max_tokens: int = 1024) -> str:
    """
    Route to the configured LLM provider.

    Resolution order:
      1. explicit LLM_PROVIDER env-var ("openai" | "anthropic" | "ollama")
      2. auto-detect: Anthropic key → Anthropic, else OpenAI key → OpenAI

    Ollama is never auto-detected (no API key to probe) — it only runs when
    LLM_PROVIDER=ollama is set explicitly.

    Raises:
        LLMUnavailableError: if no API key is configured, or Ollama is selected
            but its server is not reachable.
    """
    provider = config.llm.provider.lower()

    if provider == "ollama":
        return _call_ollama(prompt, max_tokens)
    if provider == "anthropic" and config.llm.anthropic_api_key:
        return _call_anthropic(prompt, max_tokens)
    if provider == "openai" and config.llm.openai_api_key:
        return _call_openai(prompt, max_tokens)

    if config.llm.anthropic_api_key:
        return _call_anthropic(prompt, max_tokens)
    if config.llm.openai_api_key:
        return _call_openai(prompt, max_tokens)

    raise LLMUnavailableError(
        "No LLM API key configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY, "
        "or set LLM_PROVIDER=ollama to use a local model."
    )


def strip_fences(raw: str) -> str:
    """Remove markdown code fences that LLMs sometimes wrap JSON responses in."""
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else parts[0]
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _call_openai(prompt: str, max_tokens: int) -> str:
    import openai
    client = openai.OpenAI(
        api_key=config.llm.openai_api_key,
        timeout=config.llm.timeout,
    )
    resp = client.chat.completions.create(
        model=config.llm.model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0.1,
    )
    return resp.choices[0].message.content


def _call_anthropic(prompt: str, max_tokens: int) -> str:
    import anthropic
    client = anthropic.Anthropic(
        api_key=config.llm.anthropic_api_key,
        timeout=config.llm.timeout,
    )
    resp = client.messages.create(
        model=config.llm.anthropic_model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def _call_ollama(prompt: str, max_tokens: int) -> str:
    import ollama
    client = ollama.Client(
        host=f"http://{config.llm.ollama_host}:{config.llm.ollama_port}",
        timeout=config.llm.timeout,
    )
    try:
        resp = client.chat(
            model=config.llm.ollama_model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": max_tokens},
        )
    except Exception as e:
        raise LLMUnavailableError(
            f"Ollama server not reachable at {config.llm.ollama_host}:{config.llm.ollama_port} "
            f"(model={config.llm.ollama_model}). Is `ollama serve` running? Error: {e}"
        ) from e
    return resp["message"]["content"]

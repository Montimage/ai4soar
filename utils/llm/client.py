"""
Shared LLM client used by Path B (technique attribution), Path D / playbook_generation,
and the offline evaluator (scripts/evaluate_llm_attribution.py).

Supports OpenAI, Anthropic and local Ollama; auto-detects OpenAI/Anthropic based on
available API keys. Ollama has no API key, so it must be selected explicitly via
LLM_PROVIDER=ollama. Swap providers or add a new one (Bedrock, …) only here.

Two entry points:
  call_llm(prompt, max_tokens)  -> str          simple, config-driven (Path D, verifier)
  call_model(spec, prompt)      -> LLMResponse  explicit per-model spec + call metadata
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.config import config
from core.exceptions import LLMUnavailableError

logger = logging.getLogger(__name__)

# Ollama's own default is 2048 tokens, far below the ~9.3K attribution prompt.
DEFAULT_NUM_CTX = 16384
DEFAULT_MAX_TOKENS = 1024


@dataclass
class LLMResponse:
    """One model call: the answer plus everything needed to audit it."""

    text: str                                    # answer channel (may be empty)
    usage: Dict[str, int] = field(default_factory=lambda: {"in": 0, "out": 0})
    latency: float = 0.0                         # seconds
    finish: Optional[str] = None                 # "stop" | "length" | provider-specific
    reasoning: str = ""                          # thinking channel, when exposed


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
# Spec resolution
# ---------------------------------------------------------------------------
def resolve_spec(max_tokens: Optional[int] = None,
                 num_ctx: Optional[int] = None,
                 reasoning_effort: Optional[str] = None,
                 temperature: Optional[float] = None,
                 seed: Optional[int] = 0) -> Dict:
    """Build a model spec from config, resolving which provider to use.

    Resolution order:
      1. explicit LLM_PROVIDER env-var ("openai" | "anthropic" | "ollama")
      2. auto-detect: Anthropic key → Anthropic, else OpenAI key → OpenAI

    Ollama is never auto-detected (no API key to probe) — it only runs when
    LLM_PROVIDER=ollama is set explicitly.

    Raises:
        LLMUnavailableError: if no API key is configured and Ollama was not selected.
    """
    provider = config.llm.provider.lower()
    if provider == "ollama":
        model = config.llm.ollama_model
    elif provider == "anthropic" and config.llm.anthropic_api_key:
        model = config.llm.anthropic_model
    elif provider == "openai" and config.llm.openai_api_key:
        model = config.llm.model
    elif config.llm.anthropic_api_key:
        provider, model = "anthropic", config.llm.anthropic_model
    elif config.llm.openai_api_key:
        provider, model = "openai", config.llm.model
    else:
        raise LLMUnavailableError(
            "No LLM API key configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY, "
            "or set LLM_PROVIDER=ollama to use a local model."
        )

    spec = {
        "provider":         provider,
        "model":            model,
        "max_tokens":       max_tokens if max_tokens is not None else config.llm.max_tokens,
        "num_ctx":          num_ctx if num_ctx is not None else config.llm.num_ctx,
        "reasoning_effort": reasoning_effort or config.llm.reasoning_effort,
        "timeout":          config.llm.timeout,
        "seed":             seed,
    }
    if temperature is not None:
        spec["temperature"] = temperature
    return spec


_THINKING_TAGS = ("gpt-oss", "qwen3", "gemma4", "deepseek-r1", "magistral",
                  "phi4-reasoning", "phi4-mini-reasoning", "qwq")
THINK_MAX_TOKENS = 16384
THINK_NUM_CTX    = 32768


def is_thinking_model(model: str) -> bool:
    m = model.lower()
    return any(tag in m for tag in _THINKING_TAGS)


def attribution_spec() -> Dict:
    """Spec for the Path B attribution call: benchmarked decoding settings, plus budgets
    large enough for whichever model family is configured.

    Reasoning-capable local tags get the thinking budgets unless the operator pinned
    LLM_ATTRIBUTION_MAX_TOKENS / LLM_NUM_CTX explicitly.
    """
    max_tokens = config.llm.attribution_max_tokens
    num_ctx    = config.llm.num_ctx
    spec = resolve_spec(max_tokens=max_tokens, num_ctx=num_ctx,
                        temperature=0, seed=0)
    if spec["provider"] == "ollama" and is_thinking_model(spec["model"]):
        if not config.llm.attribution_max_tokens_pinned:
            spec["max_tokens"] = max(max_tokens, THINK_MAX_TOKENS)
        if not config.llm.num_ctx_pinned:
            spec["num_ctx"] = max(num_ctx, THINK_NUM_CTX)
        logger.info(
            f"[LLM] {spec['model']} looks like a thinking model → output budget "
            f"{spec['max_tokens']}, num_ctx {spec['num_ctx']}"
        )
    return spec


def call_llm(prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
    """Route to the configured LLM provider and return the answer text.

    Kept for callers that only need a string (Path D CACAO generation, the playbook
    verifier). For reasoning models whose answer channel comes back empty, falls back
    to the thinking channel rather than returning "" — those callers json.loads the
    result, so an empty string is an unrecoverable failure either way, and the thinking
    text at least has a chance of containing the object.

    Decoding settings match the pre-existing behaviour of these callers (temperature
    0.1, no seed) — only Path B uses the benchmarked temperature 0 / seed 0.
    """
    resp = call_model(resolve_spec(max_tokens=max_tokens, temperature=0.1, seed=None),
                      prompt)
    return resp.text or resp.reasoning


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------
def _is_reasoning(model: str) -> bool:
    """gpt-5*, o1/o3/o4* are reasoning models with a different chat-completions contract."""
    return model.startswith("gpt-5") or re.match(r"^o[134]", model) is not None


_REASONING_FLOOR = {"minimal": 2000, "medium": 6000, "high": 12000}


def output_budget(spec: Dict) -> int:
    """Tokens the model may actually emit for this spec.

    For reasoning models this is the caller's `max_tokens` raised to a floor that leaves
    room for the hidden reasoning — the caller's value alone describes the answer only.
    Callers report truncation against this, not against `spec["max_tokens"]`, otherwise
    the number in the log is not the cap that was hit.
    """
    want = spec.get("max_tokens") or DEFAULT_MAX_TOKENS
    if not _is_reasoning(spec.get("model", "")):
        return want
    effort = spec.get("reasoning_effort") or "minimal"
    return max(want, _REASONING_FLOOR.get(effort, _REASONING_FLOOR["medium"]))


def _reasoning_text(msg) -> str:
    """Thinking output, wherever the server put it (field name varies by backend)."""
    for attr in ("reasoning_content", "reasoning", "thinking"):
        val = getattr(msg, attr, None)
        if isinstance(val, str) and val.strip():
            return val
    extra = getattr(msg, "model_extra", None) or {}
    for attr in ("reasoning_content", "reasoning", "thinking"):
        val = extra.get(attr)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def _openai_compat(spec: Dict, prompt: str, base_url: Optional[str], api_key: str) -> LLMResponse:
    """OpenAI (and any drop-in compatible gateway). NOT used for Ollama — see
    _ollama_native for why its /v1 endpoint is unusable for long prompts."""
    import openai
    kwargs_client = {"api_key": api_key}
    if base_url:
        kwargs_client["base_url"] = base_url
    if spec.get("timeout"):
        kwargs_client["timeout"] = spec["timeout"]
    client = openai.OpenAI(**kwargs_client)

    kwargs = dict(model=spec["model"],
                  messages=[{"role": "user", "content": prompt}])
    if _is_reasoning(spec["model"]):
        kwargs["max_completion_tokens"] = output_budget(spec)
        kwargs["reasoning_effort"] = spec.get("reasoning_effort") or "minimal"
        kwargs["seed"] = 0
    else:
        kwargs["max_tokens"] = spec.get("max_tokens", DEFAULT_MAX_TOKENS)
        kwargs["temperature"] = spec.get("temperature", 0)
        seed = spec.get("seed", 0)
        if seed is not None:
            kwargs["seed"] = seed

    t0 = time.time()
    resp = client.chat.completions.create(**kwargs)
    dt = time.time() - t0
    u = resp.usage
    choice = resp.choices[0]
    return LLMResponse(
        text=choice.message.content or "",
        usage={"in": getattr(u, "prompt_tokens", 0) or 0,
               "out": getattr(u, "completion_tokens", 0) or 0},
        latency=dt,
        finish=choice.finish_reason,
        reasoning=_reasoning_text(choice.message),
    )


def _anthropic(spec: Dict, prompt: str) -> LLMResponse:
    import anthropic
    kwargs_client = {"api_key": config.llm.anthropic_api_key or _require_key("ANTHROPIC_API_KEY")}
    if spec.get("timeout"):
        kwargs_client["timeout"] = spec["timeout"]
    client = anthropic.Anthropic(**kwargs_client)
    t0 = time.time()
    # NOTE: current Anthropic models reject temperature/top_p -> omit them.
    resp = client.messages.create(model=spec["model"],
                                  max_tokens=spec.get("max_tokens", DEFAULT_MAX_TOKENS),
                                  messages=[{"role": "user", "content": prompt}])
    dt = time.time() - t0
    txt = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    think = "".join(getattr(b, "thinking", "") for b in resp.content
                    if getattr(b, "type", "") == "thinking")
    return LLMResponse(
        text=txt,
        usage={"in": resp.usage.input_tokens, "out": resp.usage.output_tokens},
        latency=dt,
        # stop_reason "max_tokens" is Anthropic's equivalent of finish_reason "length"
        finish="length" if resp.stop_reason == "max_tokens" else resp.stop_reason,
        reasoning=think,
    )


def _ollama_base_url() -> str:
    """Ollama root URL. OLLAMA_BASE_URL wins so a remote GPU box can serve.

    Accepts a value with or without the OpenAI-compat `/v1` suffix; the suffix is
    stripped because we drive Ollama's NATIVE API (see _ollama_native).
    """
    base = os.getenv("OLLAMA_BASE_URL",
                     f"http://{config.llm.ollama_host}:{config.llm.ollama_port}")
    return base.rstrip("/")[:-3].rstrip("/") if base.rstrip("/").endswith("/v1") else base.rstrip("/")


def _ollama_native(spec: Dict, prompt: str) -> LLMResponse:
    """Call Ollama through its native /api/chat endpoint.
    """
    url = _ollama_base_url() + "/api/chat"
    options: Dict = {
        "num_ctx":     spec.get("num_ctx", DEFAULT_NUM_CTX),
        "num_predict": spec.get("max_tokens", DEFAULT_MAX_TOKENS),
        "temperature": spec.get("temperature", 0),
    }
    seed = spec.get("seed", 0)
    if seed is not None:
        options["seed"] = seed
    payload = {"model": spec["model"],
               "messages": [{"role": "user", "content": prompt}],
               "stream": False,
               "options": options}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=spec.get("timeout") or 600) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"Ollama {url} returned HTTP {e.code}: {detail}") from e
    except TimeoutError as e:
        raise RuntimeError(
            f"Ollama timed out after {spec.get('timeout')}s (model={spec['model']}, "
            f"num_ctx={options['num_ctx']}). Raise LLM_TIMEOUT, or use "
            f"LLM_ATTRIBUTION_VOCAB=parents to shrink the prompt."
        ) from e
    except (urllib.error.URLError, OSError) as e:
        if isinstance(getattr(e, "reason", None), TimeoutError):
            raise RuntimeError(
                f"Ollama timed out after {spec.get('timeout')}s (model={spec['model']}, "
                f"num_ctx={options['num_ctx']}). Raise LLM_TIMEOUT, or use "
                f"LLM_ATTRIBUTION_VOCAB=parents to shrink the prompt."
            ) from e
        raise LLMUnavailableError(
            f"Ollama server not reachable at {url} (model={spec['model']}). "
            f"Is `ollama serve` running? Error: {e}"
        ) from e
    dt = time.time() - t0
    msg = data.get("message") or {}
    return LLMResponse(
        text=msg.get("content") or "",
        usage={"in": data.get("prompt_eval_count", 0) or 0,
               "out": data.get("eval_count", 0) or 0},
        latency=dt,
        # native done_reason is "stop" | "length" | "load"
        finish=data.get("done_reason"),
        reasoning=msg.get("thinking") or "",
    )


def _require_key(name: str) -> str:
    key = os.getenv(name)
    if not key:
        raise RuntimeError(f"{name} not set (add it to .env or export it) — cannot call this model")
    return key


def call_model(spec: Dict, prompt: str) -> LLMResponse:
    """Dispatch one call. `spec` keys: provider, model, max_tokens, num_ctx,
    reasoning_effort, timeout (all but provider/model optional)."""
    p = spec["provider"]
    if p == "openai":
        return _openai_compat(spec, prompt,
                              None,
                              config.llm.openai_api_key or _require_key("OPENAI_API_KEY"))
    if p == "ollama":
        return _ollama_native(spec, prompt)
    if p == "anthropic":
        return _anthropic(spec, prompt)
    raise ValueError(f"unknown provider {p}")

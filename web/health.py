"""
Integration health check endpoint — GET /api/health/integrations
Pings each external service and returns status + latency.
"""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3
from flask import Blueprint, jsonify
from pymongo import MongoClient

from core.config import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

health_bp = Blueprint('health', __name__, url_prefix='/api')


def _ping_shuffle():
    url = config.shuffle.api_base_url
    if not config.shuffle.api_token:
        return {"status": "error", "error": "SHUFFLE_API_TOKEN is not set", "url": url}
    t0 = time.monotonic()
    try:
        r = requests.get(
            f"{url}/workflows",
            headers=config.shuffle.get_headers(),
            timeout=3,
        )
        latency = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            return {"status": "ok", "latency_ms": latency, "url": url}
        if r.status_code in (401, 403):
            return {"status": "error", "error": f"HTTP {r.status_code}: check SHUFFLE_API_TOKEN", "url": url}
        return {"status": "error", "error": f"HTTP {r.status_code}", "url": url}
    except Exception as e:
        return {"status": "error", "error": str(e), "url": url}


def _ping_mongodb():
    t0 = time.monotonic()
    try:
        client = MongoClient(
            config.mongodb.host,
            config.mongodb.port,
            serverSelectionTimeoutMS=3000,
        )
        client.admin.command("ping")
        latency = int((time.monotonic() - t0) * 1000)
        client.close()
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _ping_kafka():
    raw = config.kafka.brokers.split(",")[0].strip()
    if not raw:
        return {"status": "not_configured", "error": "KAFKA_BROKERS is not set"}
    try:
        host, port_str = raw.rsplit(":", 1)
    except ValueError:
        return {"status": "error", "error": f"Cannot parse broker: {raw}", "broker": raw}
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, int(port_str)), timeout=3)
        s.close()
        latency = int((time.monotonic() - t0) * 1000)
        return {"status": "ok", "latency_ms": latency, "broker": raw}
    except Exception as e:
        return {"status": "error", "error": str(e), "broker": raw}


def _ping_nats():
    host = config.nats.host
    port = config.nats.port
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=3)
        # NATS sends an INFO banner on connect — read a few bytes to confirm
        banner = s.recv(256)
        s.close()
        latency = int((time.monotonic() - t0) * 1000)
        if banner.startswith(b"INFO"):
            return {"status": "ok", "latency_ms": latency, "url": config.nats.url}
        return {"status": "error", "error": "Unexpected banner", "url": config.nats.url}
    except Exception as e:
        return {"status": "error", "error": str(e), "url": config.nats.url}


def _active_llm_provider():
    """The provider LLM calls actually go to (same resolution as utils.llm.client)."""
    from utils.llm.client import resolve_spec
    try:
        return resolve_spec()["provider"]
    except Exception:
        return None


def _llm_result(result, active):
    """Mark the provider LLM calls actually go to (shown as a badge on the dashboard)."""
    result["active"] = active
    return result


def _ping_anthropic(active):
    """Look up the configured model: free, and proves both the key and the model id."""
    import anthropic
    model = config.llm.anthropic_model
    label = model
    if not config.llm.anthropic_api_key:
        return {"status": "not_configured", "error": "ANTHROPIC_API_KEY is not set", "provider": label}
    t0 = time.monotonic()
    try:
        client = anthropic.Anthropic(api_key=config.llm.anthropic_api_key, timeout=5, max_retries=0)
        client.models.retrieve(model)
        latency = int((time.monotonic() - t0) * 1000)
        return {"status": "ok", "latency_ms": latency, "provider": label}
    except anthropic.AuthenticationError:
        return {"status": "error", "error": "Invalid ANTHROPIC_API_KEY", "provider": label}
    except anthropic.NotFoundError:
        return {"status": "error", "error": f"Unknown model {model}", "provider": label}
    except Exception as e:
        return {"status": "error", "error": str(e), "provider": label}


def _ping_openai(active):
    """Look up the configured model: free, and proves both the key and the model id."""
    import openai
    model = config.llm.model
    label = model
    if not config.llm.openai_api_key:
        return {"status": "not_configured", "error": "OPENAI_API_KEY is not set", "provider": label}
    t0 = time.monotonic()
    try:
        client = openai.OpenAI(api_key=config.llm.openai_api_key, timeout=5, max_retries=0)
        client.models.retrieve(model)
        latency = int((time.monotonic() - t0) * 1000)
        return {"status": "ok", "latency_ms": latency, "provider": label}
    except openai.AuthenticationError:
        return {"status": "error", "error": "Invalid OPENAI_API_KEY", "provider": label}
    except openai.NotFoundError:
        return {"status": "error", "error": f"Unknown model {model}", "provider": label}
    except Exception as e:
        return {"status": "error", "error": str(e), "provider": label}


def _ping_ollama(active):
    """List local models. Only the active provider must be running with its model pulled;
    an idle Ollama that isn't running is reported as not configured, not as a failure."""
    from utils.llm.client import _ollama_base_url
    model = config.llm.ollama_model
    url = _ollama_base_url()
    label = model
    t0 = time.monotonic()
    try:
        r = requests.get(f"{url}/api/tags", timeout=2)
        latency = int((time.monotonic() - t0) * 1000)
    except Exception as e:
        if not active:
            return {"status": "not_configured", "error": "Not running", "provider": label}
        return {"status": "error", "error": str(e), "provider": label}
    if r.status_code != 200:
        return {"status": "error", "error": f"Ollama HTTP {r.status_code}", "provider": label}
    models = [m.get("name", "") for m in r.json().get("models", [])]
    if model not in models and f"{model}:latest" not in models:
        return {"status": "error" if active else "not_configured",
                "error": f"{model} not pulled: ollama pull {model}", "provider": label}
    return {"status": "ok", "latency_ms": latency, "provider": label}


@health_bp.route('/health/integrations', methods=['GET'])
def integration_health():
    """Return connectivity status for all external SOAR integrations."""
    active = _active_llm_provider()
    checks = {
        "shuffle":   _ping_shuffle,
        "mongodb":   _ping_mongodb,
        "kafka":     _ping_kafka,
        "nats":      _ping_nats,
        "anthropic": lambda: _llm_result(_ping_anthropic(active == "anthropic"), active == "anthropic"),
        "openai":    lambda: _llm_result(_ping_openai(active == "openai"), active == "openai"),
        "ollama":    lambda: _llm_result(_ping_ollama(active == "ollama"), active == "ollama"),
    }
    # Run concurrently: the page waits for the slowest check, not the sum of them
    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        futures = {name: pool.submit(fn) for name, fn in checks.items()}
        return jsonify({name: f.result() for name, f in futures.items()}), 200

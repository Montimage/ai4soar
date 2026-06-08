"""
Integration health check endpoint — GET /api/health/integrations
Pings each external service and returns status + latency.
"""

import logging
import os
import socket
import time

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
    t0 = time.monotonic()
    try:
        r = requests.get(
            f"{url}/workflows",
            headers=config.shuffle.get_headers(),
            timeout=3,
        )
        latency = int((time.monotonic() - t0) * 1000)
        if r.status_code < 500:
            return {"status": "ok", "latency_ms": latency, "url": url}
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


def _ping_llm():
    """Check LLM availability: OpenAI key first, then local Ollama."""
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    if openai_key:
        return {"status": "ok", "provider": "OpenAI (API key set)"}

    # Try Ollama on default port
    ollama_host = os.getenv("OLLAMA_HOST", "localhost")
    ollama_port = int(os.getenv("OLLAMA_PORT", "11434"))
    t0 = time.monotonic()
    try:
        r = requests.get(f"http://{ollama_host}:{ollama_port}/api/tags", timeout=2)
        latency = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            models = [m.get("name", "") for m in r.json().get("models", [])]
            return {
                "status": "ok",
                "latency_ms": latency,
                "provider": f"Ollama ({len(models)} model{'s' if len(models) != 1 else ''})",
                "url": f"http://{ollama_host}:{ollama_port}",
            }
        return {"status": "error", "error": f"Ollama HTTP {r.status_code}", "provider": "Ollama"}
    except Exception as e:
        pass

    return {"status": "not_configured", "provider": "None", "error": "No OpenAI key or local Ollama found"}


@health_bp.route('/health/integrations', methods=['GET'])
def integration_health():
    """Return connectivity status for all external SOAR integrations."""
    return jsonify({
        "shuffle": _ping_shuffle(),
        "mongodb": _ping_mongodb(),
        "kafka":   _ping_kafka(),
        "nats":    _ping_nats(),
        "llm":     _ping_llm(),
    }), 200

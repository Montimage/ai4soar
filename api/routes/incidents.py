"""
Incident tickets: the ticketing API the playbooks' "create incident ticket" steps call
(INCIDENT_API_URL, e.g. http://172.17.0.1:5000 for Shuffle on this host).

POST /api/v1/incidents   body: the ticket as JSON (title, severity, technique, ...)
POST /api/v1/email/quarantine   the phishing playbook's mail gateway call (MAIL_API_URL)
                         -> 201 {"id": "INC-...", "status": "created"}
GET  /api/v1/incidents   ?since=<ISO time>&limit=20: newest first. Every page of the UI
                         polls it and pops up new tickets (base.html).
"""

import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from pymongo import DESCENDING, MongoClient

from core.config import config

logger = logging.getLogger(__name__)
incidents_bp = Blueprint('incidents', __name__, url_prefix='/api/v1')
_client = None


def _col():
    global _client
    if _client is None:
        _client = MongoClient(config.mongodb.host, config.mongodb.port, serverSelectionTimeoutMS=3000)
    return _client[config.mongodb.database]["incidents"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@incidents_bp.route('/incidents', methods=['POST'])
def create_incident():
    ticket = request.get_json(silent=True)
    if not isinstance(ticket, dict):
        # A playbook body that is not JSON is kept as text rather than refused
        ticket = {"title": "Incident", "body": request.get_data(as_text=True)[:5000]}
    now = _now()
    inc_id = "INC-" + now[:19].replace("-", "").replace(":", "").replace("T", "-") + "-" + uuid.uuid4().hex[:4]
    doc = {"_id": inc_id, "received_at": now,
           "from": request.remote_addr, "ticket": ticket}
    _col().insert_one(doc)
    logger.info(f"[Incidents] {doc['_id']} from {doc['from']}: {ticket.get('title', '')}")
    return jsonify({"id": doc["_id"], "status": "created", "received_at": now}), 201


@incidents_bp.route('/email/quarantine', methods=['POST'])
def quarantine_email():
    """The mail gateway API of the phishing playbook (MAIL_API_URL): quarantining the
    email is recorded, and shown like a ticket ("Email quarantined")."""
    req = request.get_json(silent=True) or {}
    now = _now()
    doc = {"_id": "MAIL-" + now[:19].replace("-", "").replace(":", "").replace("T", "-") + "-" + uuid.uuid4().hex[:4],
           "received_at": now, "from": request.remote_addr,
           "ticket": {"title": f"Email quarantined: {req.get('subject', '')}".strip(),
                      "severity": "medium", **{k: v for k, v in req.items() if k != "title"}}}
    _col().insert_one(doc)
    return jsonify({"id": doc["_id"], "status": "quarantined", "received_at": now}), 200


@incidents_bp.route('/incidents', methods=['GET'])
def list_incidents():
    q = {"received_at": {"$gt": request.args["since"]}} if request.args.get("since") else {}
    limit = min(int(request.args.get("limit", 20)), 100)
    items = list(_col().find(q).sort("received_at", DESCENDING).limit(limit))
    for d in items:
        d["id"] = d.pop("_id")
    return jsonify({"incidents": items, "now": _now()}), 200

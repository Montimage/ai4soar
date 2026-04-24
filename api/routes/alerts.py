"""
Alert-related API routes — historical MongoDB, live Kafka, live NATS (SSE).
"""

import asyncio
import json
import logging
import queue
import threading
import uuid

from flask import Response, request, jsonify, stream_with_context
from api.routes import alerts_bp
from core.alerts_consumer.wazuh import fetch_alerts as wazuh_fetch_alerts
from core.database.alert_service import AlertService
from core.config import config
from core.intelligent_orchestration.enrichment.pipeline import normalize_alert

logger = logging.getLogger(__name__)

alert_service = AlertService()


# ------------------------------------------------------------------
# NATS live-stream state (shared across SSE connections)
# ------------------------------------------------------------------

# Per-subject NATS fan-out state: subject → {queues: {id: Queue}, started: bool}
_nats_subjects: dict = {}
_nats_subjects_lock = threading.Lock()


async def _nats_background_listener(nats_url: str, subject: str) -> None:
    """Async NATS subscriber — runs in a daemon thread's event loop."""
    try:
        import nats
        nc = await nats.connect(nats_url, connect_timeout=5, max_reconnect_attempts=10)
        logger.info(f"[NATS] Connected to {nats_url}, subscribed to '{subject}'")

        async def _handler(msg):
            raw = msg.data.decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
                normalized, _ = normalize_alert(parsed)
                loop = asyncio.get_event_loop()
                loop.run_in_executor(None, alert_service.save_alert, normalized)
                compact = json.dumps(normalized)
            except (json.JSONDecodeError, ValueError):
                compact = raw.replace('\n', ' ').replace('\r', '')
            with _nats_subjects_lock:
                queues = (_nats_subjects.get(subject) or {}).get('queues', {})
                for q in list(queues.values()):
                    try:
                        q.put_nowait(compact)
                    except queue.Full:
                        pass

        await nc.subscribe(subject, cb=_handler)
        while True:
            await asyncio.sleep(5)
    except Exception as exc:
        logger.warning(f"[NATS] Listener for '{subject}' stopped: {exc}")


def _ensure_nats_listener(subject: str) -> None:
    with _nats_subjects_lock:
        entry = _nats_subjects.get(subject)
        if entry and entry.get('started'):
            return
        if not entry:
            _nats_subjects[subject] = {'queues': {}, 'started': False}
        _nats_subjects[subject]['started'] = True

    nats_url = config.nats.url

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_nats_background_listener(nats_url, subject))

    t = threading.Thread(target=_run, name=f"nats-{subject}", daemon=True)
    t.start()


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@alerts_bp.route('/fetch_alerts', methods=['GET'])
def fetch_alerts():
    """Retrieve recent Wazuh alerts with specified characteristics."""
    try:
        usecase = request.args.get('usecase')
        if not usecase:
            return jsonify({'error': 'usecase parameter is required'}), 400

        alerts = wazuh_fetch_alerts(usecase)
        if alerts:
            return jsonify(alerts), 200
        else:
            return jsonify({'error': 'No alerts found or an error occurred'}), 500
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({'error': str(e)}), 500


@alerts_bp.route('/historical_alerts', methods=['GET'])
def get_historical_alerts():
    """
    Paginated historical alerts.

    Query params:
        page      int   default 1
        limit     int   default 50  (capped at 500)
        sort_by   str   timestamp | severity | tactic | technique | description | host
        sort_dir  int   -1 desc (default) | 1 asc
        search    str   free-text regex across description, tactic, technique, host, channel
        tactic    str   filter to a specific MITRE tactic (regex)

    Response: { alerts: [...], total: N, page: N, limit: N, pages: N }
    """
    try:
        page     = max(1, int(request.args.get('page', 1)))
        limit    = min(500, max(10, int(request.args.get('limit', 50))))
        sort_by  = request.args.get('sort_by', 'timestamp')
        sort_dir = int(request.args.get('sort_dir', -1))
        search   = request.args.get('search', '').strip()
        tactic   = request.args.get('tactic', '').strip()

        result = alert_service.get_historical_alerts_paged(
            page=page, limit=limit, sort_by=sort_by,
            sort_dir=sort_dir, search=search, tactic=tactic,
        )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error getting historical alerts: {e}")
        return jsonify({'error': str(e)}), 500


@alerts_bp.route('/alerts/tactics', methods=['GET'])
def get_distinct_tactics():
    """Return distinct MITRE tactic values present in the alerts collection."""
    try:
        return jsonify(alert_service.get_distinct_tactics()), 200
    except Exception as e:
        logger.error(f"Error getting tactics: {e}")
        return jsonify({'error': str(e)}), 500


@alerts_bp.route('/alerts/<alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    """Delete a historical alert from MongoDB."""
    try:
        deleted = alert_service.delete_alert(alert_id)
        if deleted:
            return jsonify({'status': 'deleted', 'id': alert_id}), 200
        return jsonify({'error': 'Alert not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500


@alerts_bp.route('/nats_stream', methods=['GET'])
def nats_stream():
    """
    SSE endpoint — streams live alerts from a NATS subject.

    Query params:
        subject  str  NATS subject to subscribe to (default: ai4soar.alerts)

    Connect with: EventSource('/api/nats_stream?subject=ai4soar.alerts')
    """
    subject = request.args.get('subject', 'ai4soar.alerts').strip() or 'ai4soar.alerts'
    _ensure_nats_listener(subject)

    client_id = str(uuid.uuid4())
    client_q: queue.Queue = queue.Queue(maxsize=200)

    with _nats_subjects_lock:
        if subject not in _nats_subjects:
            _nats_subjects[subject] = {'queues': {}, 'started': True}
        _nats_subjects[subject]['queues'][client_id] = client_q

    def _generate():
        try:
            yield f"data: {json.dumps({'type': 'connected', 'subject': subject})}\n\n"
            while True:
                try:
                    msg = client_q.get(timeout=25)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _nats_subjects_lock:
                (_nats_subjects.get(subject) or {}).get('queues', {}).pop(client_id, None)
            logger.debug(f"[NATS SSE] client {client_id} disconnected from '{subject}'")

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )

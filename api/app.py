"""
Main Flask application for AI4SOAR platform.
"""

import logging
import os
from bson import ObjectId
from flask import Flask, redirect
from flask.json.provider import DefaultJSONProvider
from core.logging_config import setup_logging
from core.config import config


class _MongoJSONProvider(DefaultJSONProvider):
    """Extends Flask's JSON provider to handle BSON ObjectId and datetime."""
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        return super().default(obj)
from api.routes import (
    alerts_bp,
    playbooks_bp,
    kafka_bp,
    verification_bp,
    encoding_bp,
    recommendations_bp,
)

# Optional web UI — remove the web/ folder and these two lines to fully detach
try:
    from web import web_bp, health_bp as _web_health_bp
    _WEB_ENABLED = True
except ImportError:
    _WEB_ENABLED = False

# Setup logging
setup_logging(log_level=logging.INFO, log_file='logs/ai4soar.log')
logger = logging.getLogger(__name__)


def create_app():
    """
    Create and configure the Flask application.
    
    Returns:
        Flask: Configured Flask application
    """
    app = Flask(__name__)
    app.json_provider_class = _MongoJSONProvider
    app.json = _MongoJSONProvider(app)
    
    # Register API blueprints
    app.register_blueprint(alerts_bp)
    app.register_blueprint(playbooks_bp)
    app.register_blueprint(kafka_bp)
    app.register_blueprint(verification_bp)
    app.register_blueprint(encoding_bp)
    app.register_blueprint(recommendations_bp)

    # Example alerts (data/example_alerts.json): the missing ones are added to MongoDB
    if os.getenv("EXAMPLE_ALERTS", "true").strip().lower() not in ("0", "false", "no"):
        try:
            from core.database import example_alerts
            n = example_alerts.load()
            if n:
                logger.info(f"Loaded {n} example alert(s) into MongoDB")
        except Exception as e:      # MongoDB down: the app still starts
            logger.warning(f"Example alerts not loaded: {e}")
    from api.routes.incidents import incidents_bp
    app.register_blueprint(incidents_bp)

    # The internal address (SERVER_INTERNAL_HOST, e.g. docker0 172.17.0.1) lets Shuffle's
    # containers post incident tickets. A request that does not come from this machine
    # (Apache and local tools connect from 127.0.0.1) gets the incidents API and nothing
    # else, whatever host name it uses (e.g. 172.17.0.1.nip.io)
    if os.getenv("SERVER_INTERNAL_HOST", "").strip():
        from flask import abort, request as _req

        @app.before_request
        def _internal_only_incidents():
            if _req.remote_addr not in ("127.0.0.1", "::1") and not _req.path.startswith(
                    ("/api/v1/incidents", "/api/v1/email/")):
                abort(403)

    # Register web UI blueprints (no-op if web/ folder is absent)
    if _WEB_ENABLED:
        app.register_blueprint(web_bp)
        app.register_blueprint(_web_health_bp)
        logger.info("Web UI registered at /ui/")

    logger.info("Flask application created and blueprints registered")
    
    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        return {'status': 'healthy', 'service': 'AI4SOAR'}, 200
    
    @app.route('/', methods=['GET'])
    def index():
        if _WEB_ENABLED:
            return redirect('/ui/')
        return {
            'service': 'AI4SOAR',
            'version': '2.0',
            'description': 'AI-driven Security Orchestration, Automation, and Response platform'
        }, 200
    
    return app


# Create the app instance
app = create_app()


if __name__ == '__main__':
    app.run(
        host=config.server.host,
        port=config.server.port,
        debug=config.server.debug
    )

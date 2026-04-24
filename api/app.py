"""
Main Flask application for AI4SOAR platform.
"""

import logging
from bson import ObjectId
from flask import Flask
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

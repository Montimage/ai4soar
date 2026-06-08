"""
API routes for AI4SOAR platform.
"""

from flask import Blueprint

# Create blueprints
alerts_bp = Blueprint('alerts', __name__, url_prefix='/api')
playbooks_bp = Blueprint('playbooks', __name__, url_prefix='/api')
kafka_bp = Blueprint('kafka', __name__, url_prefix='/api')
verification_bp = Blueprint('verification', __name__, url_prefix='/api')
encoding_bp = Blueprint('encoding', __name__, url_prefix='/api')
recommendations_bp = Blueprint('recommendations', __name__, url_prefix='/api')

# Import routes to register them with blueprints
from . import alerts
from . import playbooks
from . import kafka_routes
from . import verification
from . import encoding
from . import recommendations

__all__ = [
    'alerts_bp',
    'playbooks_bp',
    'kafka_bp',
    'verification_bp',
    'encoding_bp',
    'recommendations_bp',
]

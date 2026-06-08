"""
AI4SOAR web UI — self-contained Flask blueprints.
Remove this folder and the two register_blueprint calls in api/app.py to fully detach.
"""

from web.blueprint import web_bp
from web.health import health_bp

__all__ = ['web_bp', 'health_bp']

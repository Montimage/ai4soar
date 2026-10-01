"""
Main server entry point for AI4SOAR platform.
"""

from api.api import app
from core.config import config

if __name__ == '__main__':
    # Run the Flask server
    app.run(
        host=config.server.host,
        port=config.server.port,
        debug=config.server.debug,
        # graph_agents.py dispatches one concurrent AI4SOAR call per rule_id
        # when multiple alerts are approved together — without this, Flask's
        # dev server serializes them, so bulk-approving several mapped-technique
        # alerts surfaces their playbook cards one at a time instead of together.
        threaded=True,
    )

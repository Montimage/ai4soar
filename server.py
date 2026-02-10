"""
Main server entry point for AI4SOAR platform.
"""

from core.api.api import app
from core.config import config

if __name__ == '__main__':
    # Run the Flask server
    app.run(
        host=config.server.host,
        port=config.server.port,
        debug=config.server.debug
    )

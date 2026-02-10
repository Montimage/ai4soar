"""
Backward compatibility layer for the refactored API.
This module maintains the same interface as the old api.py for existing code.
"""

# Import the new app
from core.api.app import app

# For backward compatibility, expose the app at module level
__all__ = ['app']

"""
Wazuh service for fetching alerts.
"""

import logging
import requests
from typing import Dict, Any, Optional
from requests.auth import HTTPBasicAuth
from core.config import config
from core.exceptions import AI4SOARException

logger = logging.getLogger(__name__)


class WazuhService:
    """Service for Wazuh operations."""
    
    # Query parameters for different use cases
    QUERY_PARAMS = {
        'uc1': {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.ip": "192.168.21.231"}},
                        {"match": {"predecoder.program_name": "sshd"}},
                        {"match": {"rule.groups": "sshd"}},
                    ]
                }
            }
        },
        'uc2': {
            "size": 10,
            "sort": [{"@timestamp": {"order": "desc"}}]
        },
        'uc3': {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.ip": "192.168.62.52"}},
                        {"match": {"rule.groups": "win_evt_channel"}},
                        {"wildcard": {"rule.description": "*Remote Desktop Connection (RDP)*"}},
                    ]
                }
            }
        }
    }
    
    def __init__(self):
        """Initialize Wazuh service."""
        self.wazuh_config = config.wazuh
        self.endpoint = self.wazuh_config.endpoint
        self.headers = {'Content-Type': 'application/json'}
    
    def fetch_alerts(self, usecase: str) -> Optional[Dict[str, Any]]:
        """
        Fetch alerts from Wazuh for a specific use case.
        
        Args:
            usecase: Use case identifier ('uc1', 'uc2', 'uc3')
            
        Returns:
            Alerts dictionary or None if failed
            
        Raises:
            AI4SOARException: If fetching fails
        """
        usecase = usecase.lower()
        
        # Get server and credentials
        server = self.wazuh_config.get_server(usecase)
        credentials = self.wazuh_config.get_credentials(usecase)
        
        if not server or not credentials or not credentials[0]:
            logger.error(f"Invalid or incomplete configuration for usecase: {usecase}")
            raise AI4SOARException(f"Invalid configuration for usecase: {usecase}")
        
        # Get query parameters
        query_params = self.QUERY_PARAMS.get(usecase)
        if not query_params:
            logger.error(f"No query parameters defined for usecase: {usecase}")
            raise AI4SOARException(f"Unsupported usecase: {usecase}")
        
        # Make request
        url = f"{server}{self.endpoint}"
        auth = HTTPBasicAuth(*credentials)
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                json=query_params,
                auth=auth,
                verify=False  # Disable SSL verification
            )
            response.raise_for_status()
            
            alerts = response.json()
            logger.info(f"Retrieved alerts from Wazuh for usecase {usecase}")
            return alerts
            
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve alerts from Wazuh: {e}")
            raise AI4SOARException(f"Failed to retrieve Wazuh alerts: {e}") from e

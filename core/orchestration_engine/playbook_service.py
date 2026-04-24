"""
Playbook service for managing playbook operations.
"""

import logging
import requests
from typing import Dict, Any, List, Optional
from core.config import config
from core.exceptions import PlaybookError, PlaybookNotFoundError, PlaybookExecutionError

logger = logging.getLogger(__name__)


class PlaybookService:
    """Service for playbook operations."""
    
    def __init__(self):
        """Initialize playbook service."""
        self.shuffle_config = config.shuffle
        self.headers = self.shuffle_config.get_headers()
    
    def get_all_playbooks(self) -> List[Dict[str, Any]]:
        """
        Get all available playbooks.
        
        Returns:
            List of playbook information dictionaries
            
        Raises:
            PlaybookError: If fetching playbooks fails
        """
        execute_url = f"{self.shuffle_config.api_base_url}/workflows"
        
        try:
            response = requests.get(execute_url, headers=self.headers)
            response.raise_for_status()
            
            playbooks = response.json()
            logger.info(f"Retrieved {len(playbooks)} playbooks")
            
            # Return simplified playbook data
            playbook_data = [
                {
                    "id": playbook["id"],
                    "name": playbook["name"],
                    "description": playbook.get("description", "")
                }
                for playbook in playbooks
            ]
            
            return playbook_data
            
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve playbooks: {e}")
            raise PlaybookError(f"Failed to retrieve playbooks: {e}") from e
    
    def get_playbook_by_id(self, playbook_id: str) -> Dict[str, Any]:
        """
        Get a specific playbook by ID.
        
        Args:
            playbook_id: Playbook identifier
            
        Returns:
            Playbook information dictionary
            
        Raises:
            PlaybookNotFoundError: If playbook not found
            PlaybookError: If fetching playbook fails
        """
        playbooks = self.get_all_playbooks()
        
        for playbook in playbooks:
            if playbook["id"] == playbook_id:
                logger.info(f"Found playbook: {playbook['name']}")
                return playbook
        
        logger.warning(f"Playbook not found: {playbook_id}")
        raise PlaybookNotFoundError(f"Playbook with ID {playbook_id} not found")
    
    def execute_playbook(self, playbook_id: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a playbook.
        
        Args:
            playbook_id: Playbook identifier
            data: Optional execution data
            
        Returns:
            Execution response
            
        Raises:
            PlaybookExecutionError: If execution fails
        """
        execute_url = f"{self.shuffle_config.api_base_url}/workflows/{playbook_id}/execute"
        
        try:
            response = requests.post(execute_url, headers=self.headers, json=data or {})
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Playbook {playbook_id} executed successfully")
            return result
            
        except requests.RequestException as e:
            logger.error(f"Failed to execute playbook {playbook_id}: {e}")
            raise PlaybookExecutionError(f"Failed to execute playbook: {e}") from e
    
    def get_execution_results(self, execution_id: str) -> Dict[str, Any]:
        """Fetch a single execution's results from Shuffle by execution_id.

        Tries GET /streams/{id} first; falls back to POST /streams/results.
        """
        url_get = f"{self.shuffle_config.api_base_url}/streams/{execution_id}"
        try:
            resp = requests.get(url_get, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                logger.info(f"Execution results retrieved for {execution_id}")
                return resp.json()
            logger.warning(f"GET /streams/{execution_id} returned {resp.status_code}, trying POST fallback")
        except requests.RequestException as e:
            logger.warning(f"GET /streams/{execution_id} failed: {e}, trying POST fallback")

        url_post = f"{self.shuffle_config.api_base_url}/streams/results"
        try:
            resp = requests.post(url_post, headers=self.headers,
                                 json={"execution_id": execution_id}, timeout=15)
            resp.raise_for_status()
            logger.info(f"Execution results retrieved (POST) for {execution_id}")
            return resp.json()
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve execution results for {execution_id}: {e}")
            raise PlaybookError(f"Failed to retrieve execution results: {e}") from e

    def get_playbook_results(self, execution_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get playbook execution results."""
        execution_id = execution_data.get("execution_id", "")
        if execution_id:
            return self.get_execution_results(execution_id)

        execute_url = f"{self.shuffle_config.api_base_url}/streams/results"
        try:
            response = requests.post(execute_url, headers=self.headers, json=execution_data, timeout=15)
            response.raise_for_status()
            result = response.json()
            logger.info("Playbook results retrieved successfully")
            return result.get("result", result)
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve playbook results: {e}")
            raise PlaybookError(f"Failed to retrieve playbook results: {e}") from e

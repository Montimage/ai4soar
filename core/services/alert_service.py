"""
Alert service for managing alert operations.
"""

import logging
from typing import Dict, Any, List, Optional
from pymongo import MongoClient
from core.config import config
from core.exceptions import AlertError, AlertNotFoundError, DatabaseError

logger = logging.getLogger(__name__)


class AlertService:
    """Service for alert operations."""
    
    def __init__(self):
        """Initialize alert service."""
        self.mongodb_config = config.mongodb
        self._client = None
        self._alerts_collection = None
        self._playbooks_collection = None
    
    def _get_connection(self):
        """Get MongoDB connection and collections."""
        if self._client is None:
            try:
                self._client = MongoClient(
                    self.mongodb_config.host,
                    self.mongodb_config.port
                )
                db = self._client[self.mongodb_config.database]
                self._alerts_collection = db[self.mongodb_config.alerts_collection]
                self._playbooks_collection = db[self.mongodb_config.playbooks_collection]
                logger.info("MongoDB connection established")
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB: {e}")
                raise DatabaseError(f"Failed to connect to MongoDB: {e}") from e
        
        return self._alerts_collection, self._playbooks_collection
    
    def get_all_historical_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all historical alerts from database.
        
        Returns:
            List of alert dictionaries
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            alerts_collection, _ = self._get_connection()
            alerts = list(alerts_collection.find({}))
            logger.info(f"Retrieved {len(alerts)} historical alerts")
            return alerts
        except Exception as e:
            logger.error(f"Failed to retrieve historical alerts: {e}")
            raise DatabaseError(f"Failed to retrieve historical alerts: {e}") from e
    
    def get_alert_by_id(self, alert_id: str) -> Dict[str, Any]:
        """
        Get a specific alert by ID.
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            Alert dictionary
            
        Raises:
            AlertNotFoundError: If alert not found
            DatabaseError: If database operation fails
        """
        try:
            alerts_collection, _ = self._get_connection()
            alert = alerts_collection.find_one({"_id": alert_id})
            
            if not alert:
                logger.warning(f"Alert not found: {alert_id}")
                raise AlertNotFoundError(f"Alert with ID {alert_id} not found")
            
            logger.info(f"Retrieved alert: {alert_id}")
            return alert
        except AlertNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve alert {alert_id}: {e}")
            raise DatabaseError(f"Failed to retrieve alert: {e}") from e
    
    def get_playbook_id_for_alert(self, alert_id: str) -> Optional[str]:
        """
        Get playbook ID associated with an alert.
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            Playbook ID or None
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            alert = self.get_alert_by_id(alert_id)
            playbook_id = alert.get("playbook_id")
            logger.info(f"Playbook ID for alert {alert_id}: {playbook_id}")
            return playbook_id
        except AlertNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Failed to get playbook ID for alert {alert_id}: {e}")
            raise DatabaseError(f"Failed to get playbook ID: {e}") from e
    
    def close(self):
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._alerts_collection = None
            self._playbooks_collection = None
            logger.info("MongoDB connection closed")

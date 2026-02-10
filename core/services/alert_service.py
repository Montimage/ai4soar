"""
Alert service for managing alert operations.
"""

import logging
import numpy as np
from typing import Dict, Any, List, Optional
from pymongo import MongoClient
from core.config import config
from core.exceptions import AlertError, AlertNotFoundError, DatabaseError
from core.intelligent_orchestration.alert_processor import convert_one_hot_alert, convert_one_hot_alerts, encode_alerts
from core.intelligent_orchestration.similarity_learning import calculate_similarity_scores

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
    
    def encode_alert(self, alert: Dict[str, Any]) -> np.ndarray:
        """
        Encode a single alert.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Encoded alert as numpy array
            
        Raises:
            AlertError: If encoding fails
        """
        try:
            one_hot_alert = convert_one_hot_alert(alert)
            encoded_alert = encode_alerts(np.array([one_hot_alert]))
            logger.debug("Alert encoded successfully")
            return encoded_alert
        except Exception as e:
            logger.error(f"Failed to encode alert: {e}")
            raise AlertError(f"Failed to encode alert: {e}") from e
    
    def encode_historical_alerts(self) -> np.ndarray:
        """
        Encode all historical alerts.
        
        Returns:
            Encoded alerts as numpy array
            
        Raises:
            AlertError: If encoding fails
        """
        try:
            historical_alerts = self.get_all_historical_alerts()
            one_hot_alerts = convert_one_hot_alerts(historical_alerts)
            encoded_alerts = encode_alerts(one_hot_alerts)
            logger.info(f"Encoded {len(historical_alerts)} historical alerts")
            return encoded_alerts
        except Exception as e:
            logger.error(f"Failed to encode historical alerts: {e}")
            raise AlertError(f"Failed to encode historical alerts: {e}") from e
    
    def calculate_similarity(self, alert_id: str, method: str = 'cosine') -> np.ndarray:
        """
        Calculate similarity scores for an alert.
        
        Args:
            alert_id: Alert identifier
            method: Similarity method ('cosine', 'euclidean', 'manhattan')
            
        Returns:
            Similarity scores as numpy array
            
        Raises:
            AlertError: If calculation fails
        """
        try:
            # Get and encode new alert
            new_alert = self.get_alert_by_id(alert_id)
            new_encoded_alert = self.encode_alert(new_alert)
            
            # Encode historical alerts
            historical_encoded_alerts = self.encode_historical_alerts()
            
            # Calculate similarity
            similarity_scores = calculate_similarity_scores(
                new_encoded_alert,
                historical_encoded_alerts,
                method
            )
            
            logger.info(f"Calculated similarity scores for alert {alert_id} using {method} method")
            return similarity_scores
        except Exception as e:
            logger.error(f"Failed to calculate similarity: {e}")
            raise AlertError(f"Failed to calculate similarity: {e}") from e
    
    def get_top_k_similar_alerts(self, similarity_scores: List[float], k: int) -> List[Dict[str, Any]]:
        """
        Get top-k most similar alerts and their playbooks.
        
        Args:
            similarity_scores: List of similarity scores
            k: Number of top similar alerts to return
            
        Returns:
            List of playbook information dictionaries
            
        Raises:
            AlertError: If operation fails
        """
        try:
            # Extract similarity scores from nested list if needed
            if isinstance(similarity_scores[0], list):
                similarity_scores = similarity_scores[0]
            
            # Sort and select top-k indices
            top_k_indices = sorted(
                range(len(similarity_scores)),
                key=lambda i: similarity_scores[i],
                reverse=True
            )[:k]
            
            logger.info(f"Top {k} similar alert indices: {top_k_indices}")
            
            # Get historical alerts
            historical_alerts = self.get_all_historical_alerts()
            
            # Fetch playbook information for each similar alert
            from core.services.playbook_service import PlaybookService
            playbook_service = PlaybookService()
            
            playbook_data_list = []
            for idx in top_k_indices:
                if idx < len(historical_alerts):
                    alert_id = historical_alerts[idx]["_id"]
                    playbook_id = self.get_playbook_id_for_alert(alert_id)
                    if playbook_id:
                        try:
                            playbook_data = playbook_service.get_playbook_by_id(playbook_id)
                            playbook_data_list.append(playbook_data)
                        except Exception as e:
                            logger.warning(f"Failed to fetch playbook {playbook_id}: {e}")
            
            logger.info(f"Retrieved {len(playbook_data_list)} playbooks for top-{k} similar alerts")
            return playbook_data_list
            
        except Exception as e:
            logger.error(f"Failed to get top-k similar alerts: {e}")
            raise AlertError(f"Failed to get top-k similar alerts: {e}") from e
    
    def close(self):
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._alerts_collection = None
            self._playbooks_collection = None
            logger.info("MongoDB connection closed")

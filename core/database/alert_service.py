"""
Alert service for managing alert operations.
"""

import logging
import uuid
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
    
    # Valid sort-field names the API accepts → MongoDB dot-path
    _SORT_FIELDS = {
        "timestamp":   "timestamp",
        "severity":    "rule.level",
        "tactic":      "rule.mitre.tactic",
        "technique":   "rule.mitre.technique",
        "description": "rule.description",
        "host":        "data.hostname",
    }

    def get_historical_alerts_paged(
        self,
        page: int = 1,
        limit: int = 50,
        sort_by: str = "timestamp",
        sort_dir: int = -1,
        search: str = "",
        tactic: str = "",
    ) -> Dict[str, Any]:
        """
        Return a paginated, sorted, and optionally filtered slice of historical alerts.

        Returns:
            dict with keys: alerts, total, page, limit, pages
        """
        sort_field = self._SORT_FIELDS.get(sort_by, "timestamp")
        sort_dir   = -1 if sort_dir < 0 else 1
        skip       = (page - 1) * limit

        query: Dict[str, Any] = {}
        if search:
            rx = {"$regex": search, "$options": "i"}
            query["$or"] = [
                {"rule.description":      rx},
                {"rule.mitre.tactic":     rx},
                {"rule.mitre.technique":  rx},
                {"data.hostname":         rx},
                {"_source.Channel":       rx},
                {"_source.Application":   rx},
                {"_source.SourceName":    rx},
                {"_source.Category":      rx},
            ]
        if tactic:
            tactic_q = {"$regex": tactic, "$options": "i"}
            if "$or" in query:
                query = {"$and": [query, {"rule.mitre.tactic": tactic_q}]}
            else:
                query["rule.mitre.tactic"] = tactic_q

        try:
            col, _ = self._get_connection()
            total  = col.count_documents(query)
            alerts = list(
                col.find(query)
                   .sort(sort_field, sort_dir)
                   .skip(skip)
                   .limit(limit)
            )
            pages = max(1, (total + limit - 1) // limit)
            logger.info(
                "Paged historical alerts: page=%d/%d  total=%d  query=%s",
                page, pages, total, query,
            )
            return {"alerts": alerts, "total": total, "page": page, "limit": limit, "pages": pages}
        except Exception as e:
            logger.error(f"Failed to retrieve paged historical alerts: {e}")
            raise DatabaseError(f"Failed to retrieve historical alerts: {e}") from e

    def get_distinct_tactics(self) -> List[str]:
        """Return sorted list of distinct MITRE tactic values present in the collection."""
        try:
            col, _ = self._get_connection()
            return sorted(t for t in col.distinct("rule.mitre.tactic") if t)
        except Exception as e:
            logger.error(f"Failed to get distinct tactics: {e}")
            return []

    def get_all_historical_alerts(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Legacy flat fetch — kept for backward compatibility."""
        result = self.get_historical_alerts_paged(page=1, limit=limit)
        return result["alerts"]
    
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
    
    def save_alert(self, normalized_alert: Dict[str, Any]) -> Optional[str]:
        """
        Persist a normalized alert to MongoDB. Idempotent — upserts on _id.

        The canonical envelope stores _source fields at document top level so
        existing queries (rule.description, rule.mitre.tactic, data.hostname …)
        work without any changes.

        Args:
            normalized_alert: Output of normalize_alert() — has _source, _id, _adapter.

        Returns:
            The document _id on success, None on failure (non-fatal).
        """
        try:
            src    = normalized_alert.get("_source", normalized_alert)
            doc_id = normalized_alert.get("_id") or str(uuid.uuid4())

            doc = {
                **src,
                "_id":      doc_id,
                "_adapter": normalized_alert.get("_adapter", "unknown"),
                "_index":   normalized_alert.get("_index", ""),
            }

            col, _ = self._get_connection()
            col.replace_one({"_id": doc_id}, doc, upsert=True)
            logger.debug(f"[AlertService] Saved alert {doc_id}")
            return doc_id
        except Exception as exc:
            logger.warning(f"[AlertService] Failed to save alert: {exc}")
            return None

    def delete_alert(self, alert_id: str) -> bool:
        """Delete a single alert by _id. Returns True if deleted, False if not found."""
        try:
            col, _ = self._get_connection()
            result = col.delete_one({"_id": alert_id})
            if result.deleted_count == 0:
                logger.warning(f"[AlertService] Alert not found for deletion: {alert_id}")
                return False
            logger.info(f"[AlertService] Deleted alert {alert_id}")
            return True
        except Exception as exc:
            logger.error(f"[AlertService] Failed to delete alert {alert_id}: {exc}")
            raise DatabaseError(f"Failed to delete alert: {exc}") from exc

    def close(self):
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._alerts_collection = None
            self._playbooks_collection = None
            logger.info("MongoDB connection closed")

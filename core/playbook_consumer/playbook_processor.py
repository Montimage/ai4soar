"""
Legacy playbook processor module for backward compatibility.
New code should use core.services.AlertService instead.
"""

import os
import json
from pymongo import MongoClient
from core.config import config

ALERTS_DIR = "../../tests/alerts"

# Connect to MongoDB
def connect_to_mongodb():
    """Connect to MongoDB and return collections."""
    mongodb_config = config.mongodb
    client = MongoClient(mongodb_config.host, mongodb_config.port)
    db = client[mongodb_config.database]
    alerts_collection = db[mongodb_config.alerts_collection]
    playbooks_collection = db[mongodb_config.playbooks_collection]
    return alerts_collection, playbooks_collection

# List all historical alerts
def list_all_historical_alerts(collection):
    return list(collection.find({}))

# Iterate over each file in the alerts folder and insert them into the alerts's collection
def insert_alerts_from_dir():
    for filename in os.listdir(ALERTS_DIR):
        if filename.endswith('.json'):
            file_path = os.path.join(ALERTS_DIR, filename)
            with open(file_path, 'r') as file:
                alert = json.load(file)
                # Add the "playbook" field to the alert
                alert['playbook_id'] = "360e6220-f8c3-4fd1-b704-9a33fe790165"
                alerts_collection.insert_one(alert)

# Get playbook_id from the alert
def get_playbook_id_for_alert(alert_id):
    """Get playbook ID for a given alert."""
    try:
        alerts_collection, _ = connect_to_mongodb()
        alert_document = alerts_collection.find_one({"_id": alert_id})

        if alert_document:
            playbook_id = alert_document.get("playbook_id")
            return playbook_id
        else:
            return None

    except Exception as e:
        raise ValueError(f"Failed to get playbook_id for alert {alert_id}: {str(e)}")

# Note: Alerts from Kafka should be inserted using AlertService in the new architecture
# Example usage:
# alerts_collection, _ = connect_to_mongodb()
# insert_alerts_from_dir()
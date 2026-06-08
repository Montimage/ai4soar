"""
Legacy constants module for backward compatibility.
New code should use core.config instead.
"""

from core.config import config

# Server configuration (backward compatibility)
SERVER_IP = config.server.host
PORT = config.server.port

# Kafka consumer configuration (backward compatibility - legacy)
KAFKA_BROKER = config.kafka.legacy_broker
KAFKA_TOPIC = config.kafka.legacy_topic
KAFKA_CONFIG = config.kafka.get_legacy_config()

# Shuffle configuration (backward compatibility)
SHUFFLE_API_BASE_URL = config.shuffle.api_base_url
SHUFFLE_API_TOKEN = config.shuffle.api_token

# Relevant keys for one-hot encoding (backward compatibility)
SELECTED_FEATURES = config.alert_processing.selected_features
MITRE_TECHNIQUES = config.alert_processing.mitre_techniques

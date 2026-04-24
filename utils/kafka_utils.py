"""
Kafka utility helpers for AI4SOAR.
"""

import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def send_to_kafka(producer, topic: str, data: Dict[str, Any]) -> None:
    """
    Serialize data to JSON and send it to a Kafka topic.

    Args:
        producer: KafkaProducer instance
        topic:    Kafka topic name
        data:     Dict to publish (will be JSON-serialized)
    """
    payload = json.dumps(data).encode("utf-8")
    future = producer.send(topic, value=payload)
    future.get(timeout=10)
    logger.debug(f"Published {len(payload)} bytes to topic '{topic}'")

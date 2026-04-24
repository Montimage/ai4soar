"""
Kafka alert consumer — reads incoming alerts from the triage topic.
"""

import logging
from typing import Any, Dict, Optional

from kafka import KafkaConsumer

from core.config import config, ScenarioConfig
from core.exceptions import KafkaConsumeError, ScenarioError

logger = logging.getLogger(__name__)


class KafkaAlertConsumer:
    """Consumes security alerts from scenario-specific Kafka triage topics."""

    def consume_alerts(self, scenario: str, timeout_ms: int = 10000) -> Optional[Dict[str, Any]]:
        """
        Poll one alert message from the triage topic for the given scenario.

        Returns the deserialized message dict, or None if the topic is empty.
        """
        triage_topic, _, _ = ScenarioConfig.get_kafka_topics(scenario)
        if not triage_topic:
            raise ScenarioError(f"Invalid scenario: {scenario}")

        consumer = None
        try:
            consumer = KafkaConsumer(
                triage_topic,
                **config.kafka.get_consumer_config(),
            )
            batch = consumer.poll(timeout_ms=timeout_ms)
            if batch:
                for _tp, messages in batch.items():
                    for msg in messages:
                        logger.info(f"Consumed alert from '{triage_topic}'")
                        return msg.value
            logger.debug(f"No messages on '{triage_topic}'")
            return None
        except Exception as e:
            logger.error(f"Failed to consume alerts: {e}")
            raise KafkaConsumeError(f"Failed to consume alerts: {e}") from e
        finally:
            if consumer:
                consumer.close()

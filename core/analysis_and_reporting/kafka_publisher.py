"""
Kafka publisher — sends outbound results to the SOAR message bus.

Publishes three types of messages:
  • Triage alert forwarded to the SOC pipeline
  • STIX 2.1 response bundle (recommendation + mitigations) for downstream consumers
  • Honeypot manager control signal (start / stop deception strategy)
"""

import logging
from typing import Any, Dict

from kafka import KafkaProducer

from core.config import config, ScenarioConfig
from core.exceptions import KafkaPublishError, ScenarioError
from utils.kafka_utils import send_to_kafka
from utils.stix.builder import STIXBuilder

logger = logging.getLogger(__name__)


class KafkaPublisher:
    """Publishes alert data and STIX responses to scenario-specific Kafka topics."""

    def __init__(self) -> None:
        self._stix_builder = STIXBuilder()
        self._producer: KafkaProducer | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish_alert(self, scenario: str, alert_data: Dict[str, Any]) -> None:
        """Forward a triaged alert to the triage Kafka topic for a scenario."""
        triage_topic, _, _ = ScenarioConfig.get_kafka_topics(scenario)
        if not triage_topic:
            raise ScenarioError(f"Invalid scenario: {scenario}")
        try:
            send_to_kafka(self._get_producer(), triage_topic, alert_data)
            logger.info(f"Alert published to '{triage_topic}' (scenario={scenario})")
        except Exception as e:
            raise KafkaPublishError(f"Failed to publish alert: {e}") from e

    def publish_stix_response(
        self,
        scenario: str,
        response_body: Dict[str, Any],
        triaged_alert: Dict[str, Any],
    ) -> None:
        """Build a STIX 2.1 bundle from the recommendation and publish it to the SOAR topic."""
        _, soar_topic, _ = ScenarioConfig.get_kafka_topics(scenario)
        if not soar_topic:
            raise ScenarioError(f"Invalid scenario: {scenario}")
        try:
            bundle = self._stix_builder.build_stix_bundle(scenario, response_body, triaged_alert)
            send_to_kafka(self._get_producer(), soar_topic, bundle)
            logger.info(f"STIX bundle published to '{soar_topic}' (scenario={scenario})")
        except Exception as e:
            raise KafkaPublishError(f"Failed to publish STIX response: {e}") from e

    def publish_message_to_honeypot_manager(self, scenario: str, message: str) -> None:
        """Send a start/stop signal to the honeypot / deception manager."""
        if message.lower() not in ("start", "stop"):
            raise ValueError("message must be 'start' or 'stop'")
        _, _, deceive_topic = ScenarioConfig.get_kafka_topics(scenario)
        deceive_topic = deceive_topic or "ai4soar.sc1.3.gtm"
        try:
            send_to_kafka(self._get_producer(), deceive_topic, {"message": message.lower()})
            logger.info(f"Sent '{message}' to honeypot manager on '{deceive_topic}'")
        except Exception as e:
            raise KafkaPublishError(f"Failed to publish to honeypot manager: {e}") from e

    def close(self) -> None:
        if self._producer:
            self._producer.close()
            self._producer = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_producer(self) -> KafkaProducer:
        if self._producer is None:
            try:
                self._producer = KafkaProducer(**config.kafka.get_producer_config())
            except Exception as e:
                raise KafkaPublishError(f"Failed to create Kafka producer: {e}") from e
        return self._producer

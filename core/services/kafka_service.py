"""
Kafka service for publishing and consuming messages.
"""

import logging
import json
from typing import Dict, Any, Optional
from kafka import KafkaProducer, KafkaConsumer
from core.config import config, ScenarioConfig
from core.exceptions import KafkaPublishError, KafkaConsumeError, ScenarioError
from core.stix.builder import STIXBuilder
from core.utils.kafka_utils import send_to_kafka

logger = logging.getLogger(__name__)


class KafkaService:
    """Service for Kafka operations."""
    
    def __init__(self):
        """Initialize Kafka service."""
        self.stix_builder = STIXBuilder()
        self._producer = None
    
    def get_producer(self) -> KafkaProducer:
        """Get or create Kafka producer."""
        if self._producer is None:
            try:
                producer_config = config.kafka.get_producer_config()
                self._producer = KafkaProducer(**producer_config)
                logger.info("Kafka producer created successfully")
            except Exception as e:
                logger.error(f"Failed to create Kafka producer: {e}")
                raise KafkaPublishError(f"Failed to create Kafka producer: {e}") from e
        return self._producer
    
    def publish_alert(self, scenario: str, alert_data: Dict[str, Any]) -> None:
        """
        Publish an alert to the appropriate Kafka topic.
        
        Args:
            scenario: Scenario identifier
            alert_data: Alert data to publish
            
        Raises:
            ScenarioError: If scenario is invalid
            KafkaPublishError: If publishing fails
        """
        kafka_triage_topic, _, _ = ScenarioConfig.get_kafka_topics(scenario)
        if not kafka_triage_topic:
            raise ScenarioError(f"Invalid scenario: {scenario}")
        
        producer = self.get_producer()
        try:
            send_to_kafka(producer, kafka_triage_topic, alert_data)
            logger.info(f"Alert published to topic '{kafka_triage_topic}' for scenario '{scenario}'")
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")
            raise KafkaPublishError(f"Failed to publish alert: {e}") from e
    
    def publish_stix_response(self, scenario: str, response_body: Dict[str, Any],
                             triaged_alert: Dict[str, Any]) -> None:
        """
        Publish a STIX response with alert to Kafka.
        
        Args:
            scenario: Scenario identifier
            response_body: Response body containing action details
            triaged_alert: Triaged alert data
            
        Raises:
            ScenarioError: If scenario is invalid
            KafkaPublishError: If publishing fails
        """
        _, kafka_soar_topic, _ = ScenarioConfig.get_kafka_topics(scenario)
        if not kafka_soar_topic:
            raise ScenarioError(f"Invalid scenario: {scenario}")
        
        try:
            # Build STIX bundle
            stix_bundle = self.stix_builder.build_stix_bundle(scenario, response_body, triaged_alert)
            
            # Publish to Kafka
            producer = self.get_producer()
            send_to_kafka(producer, kafka_soar_topic, stix_bundle)
            logger.info(f"STIX response published to topic '{kafka_soar_topic}' for scenario '{scenario}'")
        except Exception as e:
            logger.error(f"Failed to publish STIX response: {e}")
            raise KafkaPublishError(f"Failed to publish STIX response: {e}") from e
    
    def publish_message_to_honeypot_manager(self, scenario: str, message: str) -> None:
        """
        Publish a message to the honeypot manager.
        
        Args:
            scenario: Scenario identifier
            message: Message to send ('start' or 'stop')
            
        Raises:
            ScenarioError: If scenario is invalid
            KafkaPublishError: If publishing fails
        """
        if message.lower() not in ['start', 'stop']:
            raise ValueError("Message must be either 'start' or 'stop'")
        
        _, _, kafka_deceive_topic = ScenarioConfig.get_kafka_topics(scenario)
        if not kafka_deceive_topic:
            kafka_deceive_topic = "ai4soar.sc1.3.gtm"  # Default fallback
        
        data = {'message': message.lower()}
        
        producer = self.get_producer()
        try:
            send_to_kafka(producer, kafka_deceive_topic, data)
            logger.info(f"Message '{message}' sent to honeypot manager on topic '{kafka_deceive_topic}'")
        except Exception as e:
            logger.error(f"Failed to publish message to honeypot manager: {e}")
            raise KafkaPublishError(f"Failed to publish message: {e}") from e
    
    def consume_alerts(self, scenario: str, timeout_ms: int = 10000) -> Optional[Dict[str, Any]]:
        """
        Consume alerts from Kafka topic.
        
        Args:
            scenario: Scenario identifier
            timeout_ms: Timeout in milliseconds
            
        Returns:
            Alert message or None if no message available
            
        Raises:
            ScenarioError: If scenario is invalid
            KafkaConsumeError: If consuming fails
        """
        kafka_triage_topic, _, _ = ScenarioConfig.get_kafka_topics(scenario)
        if not kafka_triage_topic:
            raise ScenarioError(f"Invalid scenario: {scenario}")
        
        consumer = None
        try:
            consumer_config = config.kafka.get_consumer_config(
                auto_offset_reset='latest',
                enable_auto_commit=False
            )
            consumer = KafkaConsumer(kafka_triage_topic, **consumer_config)
            
            message = consumer.poll(timeout_ms=timeout_ms)
            
            if message:
                for tp, messages in message.items():
                    for msg in messages:
                        logger.info(f"Consumed alert from topic '{kafka_triage_topic}'")
                        return msg.value
            
            logger.debug(f"No messages available on topic '{kafka_triage_topic}'")
            return None
            
        except Exception as e:
            logger.error(f"Failed to consume alerts: {e}")
            raise KafkaConsumeError(f"Failed to consume alerts: {e}") from e
        finally:
            if consumer:
                consumer.close()
    
    def close(self):
        """Close Kafka producer."""
        if self._producer:
            self._producer.close()
            self._producer = None
            logger.info("Kafka producer closed")

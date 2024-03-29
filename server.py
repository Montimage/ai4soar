from confluent_kafka import Consumer, KafkaError
from flask import Flask, request
from core.playbook_consumer.kafka_consumer import app, kafka_consumer
from core.constants import PORT
from core.api.api import app


if __name__ == '__main__':
    """
    # Start the Kafka consumer in a separate thread
    import threading
    kafka_thread = threading.Thread(target=kafka_consumer)
    kafka_thread.start()
    """

    # Run the Flask server
    app.run(port=PORT, debug=True)
from confluent_kafka import Consumer, KafkaError
from flask import Flask, request
from core.constants import PORT, KAFKA_TOPIC, KAFKA_CONFIG

app = Flask(__name__)

def kafka_consumer():
    consumer = Consumer(KAFKA_CONFIG)
    consumer.subscribe([KAFKA_TOPIC])

    while True:
        msg = consumer.poll(1.0)

        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                # End of partition event - not an error
                continue
            else:
                print(f'Error: {msg.error()}')
                break

        process_kafka_message(msg)

    consumer.close()

# Process the Kafka message
def process_kafka_message(msg):
    kafka_message = msg.value().decode('utf-8')
    print(f'Received Kafka message: {kafka_message}')


if __name__ == '__main__':
    """
    # Start the Kafka consumer in a separate thread
    import threading
    kafka_thread = threading.Thread(target=kafka_consumer)
    kafka_thread.start()
    """

    # Run the Flask server
    app.run(port=PORT, debug=True)

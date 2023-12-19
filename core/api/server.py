from confluent_kafka import Consumer, KafkaError
from flask import Flask, request

app = Flask(__name__)

# Kafka Consumer Configuration
KAFKA_BROKER = 'localhost:9092'
KAFKA_TOPIC = 'ai4soar_kafka_topic'

conf = {
    'bootstrap.servers': KAFKA_BROKER,
    'group.id': 'ai4soar_group',
    'auto.offset.reset': 'earliest'
}

consumer = Consumer(conf)
consumer.subscribe([KAFKA_TOPIC])


@app.route('/webhook/kafka', methods=['POST'])
def kafka_webhook():
    # Extract data from the incoming request
    kafka_data = request.get_json()

    # Process the Kafka data
    process_kafka_data(kafka_data)

    # Return a response if necessary
    return 'Webhook received successfully', 200


def process_kafka_data(kafka_data):
    # Process the Kafka data (e.g., extract information)
    print(f'Received Kafka data: {kafka_data}')


def kafka_consumer():
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

        # Process the received Kafka message
        process_kafka_message(msg)

    consumer.close()


def process_kafka_message(msg):
    # Process the Kafka message (e.g., extract information)
    kafka_message = msg.value().decode('utf-8')
    print(f'Received Kafka message: {kafka_message}')


if __name__ == '__main__':
    # Start the Kafka consumer in a separate thread
    import threading
    kafka_thread = threading.Thread(target=kafka_consumer)
    kafka_thread.start()

    # Run the Flask server
    app.run(port=5000, debug=True)
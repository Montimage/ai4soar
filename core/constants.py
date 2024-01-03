# Server configuration
PORT = 5000

# Kafka consumer configuration
KAFKA_BROKER = 'localhost:9092'
KAFKA_TOPIC = 'ai4soar_kafka_topic'
KAFKA_CONFIG = {
    'bootstrap.servers': KAFKA_BROKER,
    'group.id': 'ai4soar_group',
    'auto.offset.reset': 'earliest'
}

# Shuffle configuration
SHUFFLE_API_BASE_URL = "http://localhost:3001/api/v1/workflows"
SHUFFLE_API_TOKEN = "e8a6e9a9-e18f-4b80-99a1-9f47a2efa4e1"
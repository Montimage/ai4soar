"""
Centralized configuration for AI4SOAR
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class ServerConfig:
    """Server configuration"""
    host: str = "0.0.0.0"
    port: int = 5000
    
    def __post_init__(self):
        self.host = os.getenv('SERVER_HOST', self.host)
        self.port = int(os.getenv('SERVER_PORT', self.port))


@dataclass
class KafkaConfig:
    """Kafka configuration"""
    brokers: str = 'ai4-vm-01.kafka.com:9093'
    security_protocol: str = 'SSL'
    ssl_cafile: str = '/home/user/kafka_certs/ai4soar_CARoot.pem'
    ssl_certfile: str = '/home/user/kafka_certs/ai4soar_certificate.pem'
    ssl_keyfile: str = '/home/user/kafka_certs/ai4soar_RSAkey.pem'
    ssl_password: str = None
    group_id: str = 'ai4soar_group'
    
    # Legacy config for backward compatibility
    legacy_broker: str = 'localhost:9092'
    legacy_topic: str = 'ai4soar_kafka_topic'
    
    def __post_init__(self):
        self.ssl_password = os.getenv('KAFKA_SSL_PASSWORD', self.ssl_password)
        self.brokers = os.getenv('KAFKA_BROKERS', self.brokers)
    
    def get_ssl_config(self):
        """Get SSL configuration dictionary"""
        return {
            'protocol': self.security_protocol,
            'cafile': self.ssl_cafile,
            'certfile': self.ssl_certfile,
            'keyfile': self.ssl_keyfile,
            'password': self.ssl_password,
        }
    
    def get_producer_config(self):
        """Get Kafka producer configuration"""
        import json
        return {
            'bootstrap_servers': self.brokers,
            'security_protocol': self.security_protocol,
            'ssl_cafile': self.ssl_cafile,
            'ssl_certfile': self.ssl_certfile,
            'ssl_keyfile': self.ssl_keyfile,
            'ssl_password': self.ssl_password,
            'value_serializer': lambda v: json.dumps(v).encode('utf-8'),
        }
    
    def get_consumer_config(self):
        """Get Kafka consumer configuration"""
        import json
        return {
            'bootstrap_servers': self.brokers,
            'group_id': self.group_id,
            'auto_offset_reset': 'earliest',
            'security_protocol': self.security_protocol,
            'ssl_cafile': self.ssl_cafile,
            'ssl_certfile': self.ssl_certfile,
            'ssl_keyfile': self.ssl_keyfile,
            'ssl_password': self.ssl_password,
            'value_deserializer': lambda m: json.loads(m.decode('utf-8')),
        }
    
    def get_legacy_config(self):
        """Get legacy Kafka configuration for backward compatibility"""
        return {
            'bootstrap.servers': self.legacy_broker,
            'group.id': self.group_id,
            'auto.offset.reset': 'earliest'
        }


@dataclass
class ShuffleConfig:
    """Shuffle SOAR configuration"""
    api_base_url: str = "http://localhost:3001/api/v1"
    api_token: str = "e8a6e9a9-e18f-4b80-99a1-9f47a2efa4e1"
    
    def __post_init__(self):
        self.api_base_url = os.getenv('SHUFFLE_API_BASE_URL', self.api_base_url)
        self.api_token = os.getenv('SHUFFLE_API_TOKEN', self.api_token)
    
    def get_headers(self):
        """Get authorization headers for Shuffle API"""
        return {"Authorization": f"Bearer {self.api_token}"}


@dataclass
class CalderaConfig:
    """Caldera SOAR configuration"""
    base_url: str = 'http://192.168.126.176:8888/'
    api_key_blue: str = 'BLUEADMIN123'
    
    def __post_init__(self):
        self.base_url = os.getenv('CALDERA_BASE_URL', self.base_url)
        self.api_key_blue = os.getenv('CALDERA_API_KEY_BLUE', self.api_key_blue)
    
    @property
    def api_url(self):
        """Get API URL"""
        return self.base_url + 'api/v2/'
    
    def get_default_headers(self):
        """Get default headers for Caldera API"""
        return {'Accept': 'application/json', 'KEY': self.api_key_blue}
    
    def get_post_headers(self):
        """Get POST headers for Caldera API"""
        return {'Content-Type': 'application/json', 'KEY': self.api_key_blue}


@dataclass
class WazuhConfig:
    """Wazuh configuration"""
    servers: dict = None
    credentials: dict = None
    endpoint: str = '/wazuh-alerts-*/_search'
    
    def __post_init__(self):
        if self.servers is None:
            self.servers = {
                'uc1': 'https://192.168.21.35:9200',
                'uc2': '',
                'uc3': 'https://192.168.56.50:9200'
            }
        
        if self.credentials is None:
            self.credentials = {
                'uc1': ('admin', 'SecretPassword'),
                'uc2': ('', ''),
                'uc3': ('admin', 'admin')
            }


@dataclass
class MongoDBConfig:
    """MongoDB configuration"""
    host: str = 'localhost'
    port: int = 27017
    database: str = 'ai4soar'
    alerts_collection: str = 'alerts'
    playbooks_collection: str = 'playbooks'
    
    def __post_init__(self):
        self.host = os.getenv('MONGODB_HOST', self.host)
        self.port = int(os.getenv('MONGODB_PORT', self.port))
        self.database = os.getenv('MONGODB_DATABASE', self.database)


@dataclass
class AlertProcessingConfig:
    """Alert processing configuration"""
    selected_features: list = None
    mitre_techniques: list = None
    
    def __post_init__(self):
        if self.selected_features is None:
            self.selected_features = ["srcip", "srcport", "dstip", "hostname", "technique"]
        
        if self.mitre_techniques is None:
            self.mitre_techniques = ['Password Guessing', 'SSH', 'Password Cracking']


class Config:
    """Main configuration class"""
    
    def __init__(self):
        self.server = ServerConfig()
        self.kafka = KafkaConfig()
        self.shuffle = ShuffleConfig()
        self.caldera = CalderaConfig()
        self.wazuh = WazuhConfig()
        self.mongodb = MongoDBConfig()
        self.alert_processing = AlertProcessingConfig()


# Global configuration instance
config = Config()

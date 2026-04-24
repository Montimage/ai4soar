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
    debug: bool = False

    def __post_init__(self):
        self.host  = os.getenv('SERVER_HOST', self.host)
        self.port  = int(os.getenv('SERVER_PORT', self.port))
        self.debug = os.getenv('SERVER_DEBUG', '').lower() in ('1', 'true', 'yes')


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
    api_token: str = ""
    # Browser-facing URL (used to build links the user's browser opens directly)
    ui_base_url: str = "http://localhost:3001"
    # Default workflow to open until CACAO→Shuffle mapping is in place
    default_workflow_id: str = ""

    def __post_init__(self):
        self.api_base_url = os.getenv('SHUFFLE_API_BASE_URL', self.api_base_url)
        self.api_token = os.getenv('SHUFFLE_API_TOKEN', self.api_token)
        self.ui_base_url = os.getenv('SHUFFLE_UI_URL', self.ui_base_url)
        self.default_workflow_id = os.getenv('SHUFFLE_DEFAULT_WORKFLOW_ID', self.default_workflow_id)

    def get_headers(self):
        """Get authorization headers for Shuffle API"""
        return {"Authorization": f"Bearer {self.api_token}"}

    def workflow_url(self, workflow_id: str = "") -> str:
        wid = workflow_id or self.default_workflow_id
        if wid:
            return f"{self.ui_base_url}/workflows/{wid}"
        return f"{self.ui_base_url}/workflows"


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
class AlertProcessingConfig:
    """Alert processing configuration"""
    selected_features: list = None
    mitre_techniques: list = None

    def __post_init__(self):
        if self.selected_features is None:
            self.selected_features = ["srcip", "srcport", "dstip", "hostname", "technique"]

        if self.mitre_techniques is None:
            self.mitre_techniques = ['Password Guessing', 'SSH', 'Password Cracking']


@dataclass
class STIXConfig:
    """MITRE ATT&CK STIX knowledge base configuration"""
    data_path: str = "../attack-stix-data/enterprise-attack/enterprise-attack.json"
    domain: str = "enterprise-attack"

    def __post_init__(self):
        self.data_path = os.getenv('STIX_DATA_PATH', self.data_path)


@dataclass
class OTRFConfig:
    """OTRF Security-Datasets configuration"""
    base_path: str = "../Security-Datasets"
    dataset_output: str = "datasets/otrf_normalized.jsonl"
    max_events_per_scenario: int = 200

    def __post_init__(self):
        self.base_path = os.getenv('OTRF_PATH', self.base_path)


@dataclass
class ModelConfig:
    """Trained model paths for Path C ML-based technique classification"""
    model_dir: str = "models"
    knn_path: str = "models/knn_recommender.joblib"
    lr_path: str = "models/lr_recommender.joblib"
    ovr_lr_path: str = "models/ovr_lr_recommender.joblib"
    ovr_svm_path: str = "models/ovr_svm_recommender.joblib"
    rf_path: str = "models/rf_recommender.joblib"
    mlp_path: str = "models/mlp_recommender.joblib"
    xgb_path: str = "models/xgb_recommender.joblib"
    label_binarizer_path: str = "models/label_binarizer.joblib"
    label_encoder_path: str = "models/label_encoder.joblib"
    feature_engineer_path: str = "models/feature_engineer.joblib"
    # Which model to use at inference: "knn" | "lr" | "ovr_lr" | "ovr_svm" | "rf" | "mlp" | "xgb"
    active_model: str = "lr"

    def __post_init__(self):
        self.active_model = os.getenv('SIMILARITY_MODEL', self.active_model)


@dataclass
class MongoDBConfig:
    """MongoDB configuration"""
    host: str = 'localhost'
    port: int = 27017
    database: str = 'ai4soar'
    alerts_collection: str = 'alerts'
    playbooks_collection: str = 'playbooks'
    mitre_kb_collection: str = 'mitre_kb'

    def __post_init__(self):
        self.host = os.getenv('MONGODB_HOST', self.host)
        self.port = int(os.getenv('MONGODB_PORT', self.port))
        self.database = os.getenv('MONGODB_DATABASE', self.database)


@dataclass
class LLMConfig:
    """LLM configuration for Path B (technique attribution) and Path D (CACAO generation)"""
    provider: str = "openai"                               # "openai" | "anthropic"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    model: str = "gpt-4o-mini"                            # OpenAI model
    anthropic_model: str = "claude-haiku-4-5-20251001"    # Anthropic model
    technique_confidence_threshold: float = 0.70          # min confidence for Path B to proceed
    max_tokens: int = 1024
    timeout: float = 30.0

    def __post_init__(self):
        self.provider = os.getenv("LLM_PROVIDER", self.provider)
        self.openai_api_key = os.getenv("OPENAI_API_KEY", self.openai_api_key)
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", self.anthropic_api_key)
        self.model = os.getenv("LLM_MODEL", self.model)
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", self.anthropic_model)
        self.technique_confidence_threshold = float(
            os.getenv("LLM_CONFIDENCE_THRESHOLD", str(self.technique_confidence_threshold))
        )


@dataclass
class PlaybookLibraryConfig:
    """Operational CACAO playbook library (T-code indexed YAML templates)."""
    path: str = "playbooks"

    def __post_init__(self):
        self.path = os.getenv("PLAYBOOK_LIBRARY_PATH", self.path)


@dataclass
class OrchestrationConfig:
    """Thresholds and tuning knobs for the 3-stage orchestrator."""
    # Stage 1: Path A confidence that triggers early exit
    early_exit_threshold: float = 0.85
    # Stage 2/3: confidence below this falls through to Path D
    low_confidence_threshold: float = 0.50
    # Path C discount — tactic-level precision is lower than technique-level
    path_c_discount: float = 0.85
    # Bonus when Path B tactic and Path C tactic agree
    confirmation_bonus: float = 0.10

    def __post_init__(self):
        self.early_exit_threshold = float(
            os.getenv("ORCH_EARLY_EXIT_THRESHOLD", str(self.early_exit_threshold))
        )
        self.low_confidence_threshold = float(
            os.getenv("ORCH_LOW_CONF_THRESHOLD", str(self.low_confidence_threshold))
        )
        self.path_c_discount = float(
            os.getenv("ORCH_PATH_C_DISCOUNT", str(self.path_c_discount))
        )
        self.confirmation_bonus = float(
            os.getenv("ORCH_CONFIRMATION_BONUS", str(self.confirmation_bonus))
        )


class ScenarioConfig:
    """Maps scenario IDs to their Kafka topic triplets (triage, soar, deception)."""

    _TOPICS = {
        "sc1": ("ai4soar.sc1.1.triage", "ai4soar.sc1.2.soar", "ai4soar.sc1.3.gtm"),
        "sc2": ("ai4soar.sc2.1.triage", "ai4soar.sc2.2.soar", "ai4soar.sc2.3.gtm"),
        "sc3": ("ai4soar.sc3.1.triage", "ai4soar.sc3.2.soar", "ai4soar.sc3.3.gtm"),
    }

    @staticmethod
    def get_kafka_topics(scenario: str):
        """Return (triage_topic, soar_topic, deceive_topic) for a scenario ID."""
        return ScenarioConfig._TOPICS.get(scenario.lower(), (None, None, None))


@dataclass
class NATSConfig:
    """NATS messaging broker configuration"""
    host: str = 'localhost'
    port: int = 4222

    def __post_init__(self):
        self.host = os.getenv('NATS_HOST', self.host)
        self.port = int(os.getenv('NATS_PORT', self.port))

    @property
    def url(self):
        return f"nats://{self.host}:{self.port}"


class Config:
    """Main configuration class"""

    def __init__(self):
        self.server = ServerConfig()
        self.kafka = KafkaConfig()
        self.shuffle = ShuffleConfig()
        self.caldera = CalderaConfig()
        self.wazuh = WazuhConfig()
        self.nats = NATSConfig()
        self.mongodb = MongoDBConfig()
        self.alert_processing = AlertProcessingConfig()
        self.stix = STIXConfig()
        self.otrf = OTRFConfig()
        self.model = ModelConfig()
        self.llm = LLMConfig()
        self.orchestration = OrchestrationConfig()
        self.playbook_library = PlaybookLibraryConfig()


# Global configuration instance
config = Config()

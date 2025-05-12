import numpy as np
import requests
import json
import os
import hashlib
import uuid
from datetime import datetime
import ssl
from flask import Flask, request, jsonify
from core.playbook_consumer.playbook_processor import connect_to_mongodb, list_all_historical_alerts, get_playbook_id_for_alert
from core.intelligent_orchestration.alert_processor import convert_one_hot_alert, convert_one_hot_alerts, encode_alerts
from core.intelligent_orchestration.similarity_learning import calculate_similarity_scores
from core.orchestration_engine.shuffle import get_playbooks, execute_playbook, get_playbook_results
from core.constants import SERVER_IP, PORT, SHUFFLE_API_BASE_URL
from core.orchestration_engine.caldera_soar import execute_ability
from core.playbook_consumer.wazuh import fetch_alerts
#from confluent_kafka import Producer, Consumer, KafkaException, KafkaError
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError

app = Flask(__name__)

# Kafka configuration
KAFKA_BROKERS = 'ai4-vm-01.kafka.com:9093'
KAFKA_SECURITY_PROTOCOL = 'SSL'
KAFKA_SSL_CAFILE = '/home/user/kafka_certs/ai4soar_CARoot.pem'
KAFKA_SSL_CERTFILE = '/home/user/kafka_certs/ai4soar_certificate.pem'
KAFKA_SSL_KEYFILE = '/home/user/kafka_certs/ai4soar_RSAkey.pem'
KAFKA_SSL_PASSWORD = '4XpUglfq9x5b'

# Retrieve recent Wazuh's alerts with the specified characteristics
@app.route('/fetch_alerts', methods=['GET'])
def fetch_alerts_api():
    try:
        usecase = request.args.get('usecase')
        if not usecase:
            return jsonify({'error': 'usecase parameter is required'}), 400

        alerts = fetch_alerts(usecase)
        if alerts:
            return jsonify(alerts), 200
        else:
            return jsonify({'error': 'No alerts found or an error occurred'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Kafka producer configuration
producer_config = {
    'bootstrap_servers': KAFKA_BROKERS,
    'security_protocol': KAFKA_SECURITY_PROTOCOL,
    'ssl_cafile': KAFKA_SSL_CAFILE,
    'ssl_certfile': KAFKA_SSL_CERTFILE,
    'ssl_keyfile': KAFKA_SSL_KEYFILE,
    'ssl_password': KAFKA_SSL_PASSWORD,
    'value_serializer': lambda v: json.dumps(v).encode('utf-8')
}

# Validate and map scenarios to Kafka topics
def get_kafka_topic_for_scenario(scenario):
    valid_scenarios = ['sc11', 'sc12', 'sc13', 'sc21', 'sc22', 'sc23', 'sc31', 'sc32', 'sc33']
    if scenario.lower() not in valid_scenarios:
        return None, None

    number = scenario[2:]
    # Map to Kafka topics
    if scenario in ['sc11', 'sc31']:
        kafka_triage_topic = f"ai4triage.sc{number[0]}.{number[1]}.alerts"
    elif scenario in ['sc12']:
        #kafka_triage_topic = f"ai4fids.sc{number[0]}.{number[1]}"
        kafka_triage_topic = f"ai4fids.sc{number[0]}.{number[1]}.test"
    elif scenario == 'sc33':
        kafka_triage_topic = f"ai4deceive.sc{number[0]}.{number[1]}.mmt_alerts"
    kafka_soar_topic = f"ai4soar.sc{number[0]}.{number[1]}.responses"

    return kafka_triage_topic, kafka_soar_topic

@app.route('/publish_alerts', methods=['POST'])
def publish_alerts():
    data = request.get_json()
    scenario = request.args.get('scenario').lower()

    # Get Kafka topics based on scenario
    kafka_triage_topic, _ = get_kafka_topic_for_scenario(scenario)
    if not kafka_triage_topic:
        return jsonify({'status': 'error', 'message': 'Invalid scenario'}), 400

    producer = KafkaProducer(**producer_config)
    try:
        producer.send(kafka_triage_topic, value=data)
        producer.flush()
        return jsonify({'status': 'success', 'message': 'Alert published successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        producer.close()

@app.route('/publish_message_to_hm', methods=['POST'])
def publish_message_to_hm():
    # Retrieve the 'message' param from the query string
    message = request.args.get('message').lower()
    print(message)

    if message not in ['start', 'stop']:
        return jsonify({'status': 'error', 'message': 'Invalid message parameter, should be either "start" or "stop"'}), 400

    # Create the payload based on the message param
    data = {'message': message}
    kafka_topic = "ai4soar.sc3.3.gtm"
    # Add value_serializer to producer_config
    producer_config['value_serializer'] = lambda v: json.dumps(v).encode('utf-8')

    producer = KafkaProducer(**producer_config)

    try:
        # Publish the message as JSON to the Kafka topic
        producer.send(kafka_topic, value=data)
        producer.flush()
        return jsonify({'status': 'success', 'message': f'Inform Honeypot Manager to {message} calculating a new deceive strategy'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        producer.close()

# TODO: delete ?
@app.route('/consume_deceive_strategy', methods=['GET'])
def consume_deceive_strategy():
    #scenario = request.args.get('scenario').lower()
    # Get Kafka topics based on scenario
    #kafka_triage_topic, _ = get_kafka_topic_for_scenario(scenario)
    #kafka_topic = "ai4deceive.sc3.3.gtm"
    kafka_topic = "ai4soar.deceive.test"
    if not kafka_topic:
        return jsonify({'status': 'error', 'message': 'Invalid scenario'}), 400

    try:
        consumer = KafkaConsumer(
            kafka_topic,
            bootstrap_servers=KAFKA_BROKERS,
            security_protocol=KAFKA_SECURITY_PROTOCOL,
            ssl_check_hostname=False,
            ssl_cafile=KAFKA_SSL_CAFILE,
            ssl_certfile=KAFKA_SSL_CERTFILE,
            ssl_keyfile=KAFKA_SSL_KEYFILE,
            ssl_password=KAFKA_SSL_PASSWORD,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            group_id=None,
            #group_id='latest-alert-consumer-group',
            auto_offset_reset='latest',
            #auto_offset_reset='earliest',
            enable_auto_commit=False
        )

        # Attempt to poll for a message with a timeout
        # Timeout which should be equal to scheduler's interval on Shuffle
        message = consumer.poll(timeout_ms=5000)

        if message:
            for tp, messages in message.items():
                for msg in messages:
                    print(f"Consumed message: {msg.value}")
                    return jsonify({'status': 'success', 'message': msg.value}), 200
        else:
            return jsonify({'status': 'error', 'message': 'No messages available'}), 404

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

    finally:
        if consumer:
            consumer.close()

@app.route('/consume_alerts', methods=['GET'])
def consume_alerts():
    scenario = request.args.get('scenario').lower()
    # Get Kafka topics based on scenario
    kafka_triage_topic, _ = get_kafka_topic_for_scenario(scenario)
    if not kafka_triage_topic:
        return jsonify({'status': 'error', 'message': 'Invalid scenario'}), 400

    try:
        consumer = KafkaConsumer(
            kafka_triage_topic,
            bootstrap_servers=KAFKA_BROKERS,
            security_protocol=KAFKA_SECURITY_PROTOCOL,
            ssl_check_hostname=False,
            ssl_cafile=KAFKA_SSL_CAFILE,
            ssl_certfile=KAFKA_SSL_CERTFILE,
            ssl_keyfile=KAFKA_SSL_KEYFILE,
            ssl_password=KAFKA_SSL_PASSWORD,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            group_id=None,
            #group_id='latest-alert-consumer-group',
            #auto_offset_reset='latest',
            auto_offset_reset='earliest',
            enable_auto_commit=False
        )

        # Attempt to poll for a message with a timeout
        # Timeout which should be equal to scheduler's interval on Shuffle
        message = consumer.poll(timeout_ms=10000)

        if message:
            for tp, messages in message.items():
                for msg in messages:
                    print(f"Consumed message: {msg.value}")
                    return jsonify({'status': 'success', 'message': msg.value}), 200
        else:
            return jsonify({'status': 'error', 'message': 'No messages available'}), 404

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

    finally:
        if consumer:
            consumer.close()

def produce_stix_response_with_alert_to_kafka_sc31(response_body, wazuh_alert, kafka_topic):
    try:
        producer = KafkaProducer(**producer_config)

        # Extract relevant fields from wazuh_alert
        agent_ip = wazuh_alert['_source']['agent']['ip']
        target_user = wazuh_alert['_source']['data']['win']['eventdata']['targetUserName']
        event_id = wazuh_alert['_source']['data']['win']['system']['eventID']
        timestamp = wazuh_alert['_source'].get('@timestamp', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))

        # Concatenate the extracted fields to form the input string
        hash_input = f"{agent_ip}-{target_user}-{event_id}-{timestamp}"

        # Generating the SHA-256 hash
        sha256_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": f"identity--{uuid.uuid4()}",
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "name": "Wazuh",
                    "identity_class": "organization"
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": f"observed-data--{uuid.uuid4()}",
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "first_observed": wazuh_alert["_source"]["@timestamp"],
                    "last_observed": wazuh_alert["_source"]["@timestamp"],
                    "number_observed": 1,
                    "objects": {
                        "0": {
                            "type": "file",
                            "name": wazuh_alert["_source"]["location"],
                            "hashes": {
                                "SHA-256": sha256_hash
                            }
                        },
                        "1": {
                            "type": "ipv4-addr",
                            "value": wazuh_alert["_source"]["agent"]["ip"]
                        },
                        "2": {
                            "type": "user-account",
                            "user_id": target_user
                        }
                    },
                    "created_by_ref": f"identity--{uuid.uuid4()}"
                },
                {
                    "type": "x-defense-action",
                    "id": f"x-defense-action--{uuid.uuid4()}",
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "name": response_body["name"],
                    "ability_id": response_body["ability_id"],
                    "target": response_body["target"],
                    "observations": response_body["observations"],
                    "health": response_body["health"],
                    "source": response_body["source"],
                    "execution_status": "success"  # Assuming execution is successful
                }
            ]
        }

        producer.send(kafka_topic, stix_bundle)
        producer.flush()
        print(f"STIX response sent to topic '{kafka_topic}' successfully.")
    except Exception as e:
        print(f"Error producing STIX response to Kafka topic: {e}")
    finally:
        producer.close()

# TODO: do we need response_body ???
def produce_stix_response_with_alert_to_kafka_sc33(response_body, alert, kafka_topic):
    try:
        producer = KafkaProducer(**producer_config)

        identity_id = f"identity--{uuid.uuid4()}"
        first_observed = datetime.utcfromtimestamp(alert["details"]["start_t"]).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        last_observed = datetime.utcfromtimestamp(alert["details"]["end_t"]).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        timestamp_start = datetime.utcfromtimestamp(response_body["timestamp"]).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Pre-generate UUIDs for the objects that will be referenced
        src_ip_id = f"ipv4-addr--{uuid.uuid4()}"
        dst_ip_id = f"ipv4-addr--{uuid.uuid4()}"
        attack_type_id = f"x-attack-type--{uuid.uuid4()}"

        # Generate valid STIX bundle
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "name": "MMT-PROBE",
                    "identity_class": "organization"
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": f"observed-data--{uuid.uuid4()}",
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "first_observed": first_observed,
                    "last_observed": last_observed,
                    "number_observed": 1,
                    "object_refs": [
                        src_ip_id,
                        dst_ip_id,
                        attack_type_id
                    ],
                    "created_by_ref": identity_id
                },
                {
                    "type": "ipv4-addr",
                    "id": src_ip_id,
                    "value": alert["details"]["src_ip"]
                },
                {
                    "type": "ipv4-addr",
                    "id": dst_ip_id,
                    "value": alert["details"]["dst_ip"]
                },
                {
                    "type": "x-attack-type",
                    "id": attack_type_id,
                    "user_id": alert["details"]["type"],
                    "extensions": {
                        "x-attack-type-ext": {
                            "extension_type": "new-sdo"
                        }
                    }
                },
                {
                    "type": "x-defense-action",
                    "id": f"x-defense-action--{uuid.uuid4()}",
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "alert_id": alert["details"]["id"],
                    "honeypot_type": "gustavojodar/rdpy-docker:v1.0",  # hardcoded for now
                    "execution_status": "success",
                    "extensions": {
                        "x-defense-action-ext": {
                            "extension_type": "new-sdo",
                            "action_taken": "honeypot running"
                        }
                    }
                }
            ]
        }

        # Send the STIX bundle to Kafka topic
        producer.send(kafka_topic, value=stix_bundle)
        producer.flush()
        print(f"STIX response sent to topic '{kafka_topic}' successfully.")

    except Exception as e:
        print(f"Error producing STIX response to Kafka topic: {e}")
    finally:
        producer.close()

def produce_stix_response_with_alert_to_kafka_sc12(response_body, alert, kafka_topic):
    try:
        producer = KafkaProducer(**producer_config)

        # Debug logging
        print("Received alert:", json.dumps(alert, indent=2))
        print("Received response_body:", json.dumps(response_body, indent=2))

        # Extract relevant fields from alert
        flow_features = alert.get('flow_features', {})
        if not flow_features:
            print("Warning: No flow_features found in alert")
            flow_features = {}

        src_ip = flow_features.get('Src IP')
        dst_ip = flow_features.get('Dst IP')
        src_port = int(flow_features.get('Src Port', 0))
        dst_port = int(flow_features.get('Dst Port', 0))
        protocol = int(flow_features.get('Protocol', 0))
        timestamp = flow_features.get('Timestamp')
        attack_type = alert.get('attack_type')
        confidence = float(alert.get('confidence', 0.0))

        # Debug logging for extracted values
        print(f"Extracted values: src_ip={src_ip}, dst_ip={dst_ip}, src_port={src_port}, dst_port={dst_port}, protocol={protocol}")
        print(f"Attack type: {attack_type}, Confidence: {confidence}")

        # Convert timestamp to proper STIX format with error handling
        try:
            if timestamp:
                timestamp_dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
                stix_timestamp = timestamp_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            else:
                stix_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except (ValueError, TypeError) as e:
            print(f"Warning: Error parsing timestamp {timestamp}: {e}")
            stix_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        current_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Generate UUIDv5 IDs for Cyber Observable Objects
        def generate_uuidv5(name):
            if name is None:
                name = str(uuid.uuid4())  # Generate random UUID if name is None
            namespace = uuid.NAMESPACE_DNS
            return str(uuid.uuid5(namespace, str(name)))

        # Generate UUIDv5 for SCOs (Cyber Observable Objects)
        src_ip_id = f"ipv4-addr--{generate_uuidv5(src_ip)}"
        dst_ip_id = f"ipv4-addr--{generate_uuidv5(dst_ip)}"
        network_traffic_id = f"network-traffic--{generate_uuidv5(f'{src_ip}-{dst_ip}-{src_port}-{dst_port}')}"

        # Generate UUIDv4 for other objects
        identity_id = f"identity--{str(uuid.uuid4())}"
        observed_data_id = f"observed-data--{str(uuid.uuid4())}"
        defense_action_id = f"x-defense-action--{str(uuid.uuid4())}"

        # Extract and convert flow features to proper types
        flow_duration = int(flow_features.get('Flow Duration', 0))
        total_fwd_packets = int(flow_features.get('Total Fwd Packet', 0))
        total_bwd_packets = int(flow_features.get('Total Bwd packets', 0))
        flow_bytes_per_sec = float(flow_features.get('Flow Bytes/s', 0.0))
        flow_packets_per_sec = float(flow_features.get('Flow Packets/s', 0.0))

        # Debug logging for flow features
        print(f"Flow features: duration={flow_duration}, fwd_packets={total_fwd_packets}, bwd_packets={total_bwd_packets}")
        print(f"Flow rates: bytes/s={flow_bytes_per_sec}, packets/s={flow_packets_per_sec}")

        # Create STIX bundle
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "created": current_time,
                    "modified": current_time,
                    "name": "Network Flow Analyzer",
                    "identity_class": "organization"
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": observed_data_id,
                    "created": current_time,
                    "modified": current_time,
                    "first_observed": stix_timestamp,
                    "last_observed": stix_timestamp,
                    "number_observed": 1,
                    "object_refs": [
                        src_ip_id,
                        dst_ip_id,
                        network_traffic_id
                    ],
                    "created_by_ref": identity_id
                },
                {
                    "type": "ipv4-addr",
                    "id": src_ip_id,
                    "value": str(src_ip) if src_ip is not None else "0.0.0.0"
                },
                {
                    "type": "ipv4-addr",
                    "id": dst_ip_id,
                    "value": str(dst_ip) if dst_ip is not None else "0.0.0.0"
                },
                {
                    "type": "network-traffic",
                    "id": network_traffic_id,
                    "src_ref": src_ip_id,
                    "dst_ref": dst_ip_id,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocols": ["ipv4", "udp" if protocol == 17 else "tcp"],
                    "extensions": {
                        "x-network-traffic-ext": {
                            "extension_type": "property-extension",
                            "flow_duration": flow_duration,
                            "total_fwd_packets": total_fwd_packets,
                            "total_bwd_packets": total_bwd_packets,
                            "flow_bytes_per_sec": flow_bytes_per_sec,
                            "flow_packets_per_sec": flow_packets_per_sec
                        }
                    }
                },
                {
                    "type": "x-defense-action",
                    "id": defense_action_id,
                    "created": current_time,
                    "modified": current_time,
                    "name": str(response_body.get("name", "Network Flow Analysis")),
                    "target": str(response_body.get("target", src_ip)) if src_ip is not None else "0.0.0.0",
                    "observations": str(response_body.get("observations", f"Detected {attack_type}")),
                    "source": str(response_body.get("source", "network-flow-analyzer")),
                    "extensions": {
                        "x-defense-action-ext": {
                            "extension_type": "new-sdo",
                            "attack_type": str(attack_type) if attack_type is not None else "unknown",
                            "confidence": confidence,
                            "execution_status": "success"
                        }
                    }
                }
            ]
        }

        # Debug logging for final STIX bundle
        print("Generated STIX bundle:", json.dumps(stix_bundle, indent=2))

        producer.send(kafka_topic, stix_bundle)
        producer.flush()
        print(f"STIX response sent to topic '{kafka_topic}' successfully.")
    except Exception as e:
        print(f"Error producing STIX response to Kafka topic: {e}")
        import traceback
        print("Full traceback:", traceback.format_exc())
    finally:
        producer.close()

@app.route('/publish_responses_with_alert_stix', methods=['POST'])
def publish_responses_with_alert_stix():
    scenario = request.args.get('scenario').lower()
    # Get Kafka topics based on scenario
    _, kafka_soar_topic = get_kafka_topic_for_scenario(scenario)
    if not kafka_soar_topic:
        return jsonify({'status': 'error', 'message': 'Invalid scenario'}), 400

    try:
        response_body = request.form.get('response_body')
        print(response_body)
        if response_body:
            response_body = json.loads(response_body)
        else:
            return jsonify({"status": "error", "message": "Missing response_body in the request."}), 400

        wazuh_alert = request.form.get('wazuh_alert')
        print(wazuh_alert)
        if wazuh_alert:
            wazuh_alert = json.loads(wazuh_alert)
        else:
            return jsonify({"status": "error", "message": "Missing wazuh_alert in the request."}), 400

        if scenario == 'sc11':
            produce_stix_response_with_alert_to_kafka_sc11(response_body, wazuh_alert, kafka_soar_topic)
        elif scenario == 'sc12':
            produce_stix_response_with_alert_to_kafka_sc12(response_body, wazuh_alert, kafka_soar_topic)
        elif scenario == 'sc31':
            produce_stix_response_with_alert_to_kafka_sc31(response_body, wazuh_alert, kafka_soar_topic)
        elif scenario == 'sc33':
            produce_stix_response_with_alert_to_kafka_sc33(response_body, wazuh_alert, kafka_soar_topic)
        return jsonify({"status": "success", "message": "STIX response sent to Kafka topic successfully."}), 200
    except KeyError as e:
        return jsonify({"status": "error", "message": f"Missing parameter: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}), 500

# Execute Caldera blue agent
@app.route('/execute_ability', methods=['POST'])
def execute_ability_api():
    try:
        ability_id = request.form.get('ability_id')
        target = request.form.get('target')

        # If ability_id is empty and target is not empty, consider it as a no-op
        if ability_id == "" and target != "":
            return jsonify({'message': 'No action taken as ability_id is empty and target is provided.'}), 200

        # If both ability_id and target are provided, execute the ability
        if ability_id and target:
            response = execute_ability(ability_id, target)
            print(response)
            return jsonify({'message': 'Ability execution initiated successfully', 'response': response.text}), 200

        # If not valid inputs, return error
        return jsonify({'error': 'Invalid input'}), 400

    except KeyError as e:
        return jsonify({'error': f'Missing required parameter: {str(e)}'}), 400

    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List all playbook's information, including id, name and description
# or a specific playbook's information
@app.route('/playbooks', methods=['GET'])
def get_playbooks_route():
    playbook_id = request.args.get('playbook_id')
    playbooks = get_playbooks()

    if playbook_id:
        # If playbook_id is provided, fetch information about the specific playbook
        for playbook in playbooks:
            if playbook["id"] == playbook_id:
                return jsonify(playbook)
        return jsonify({"error": f"Playbook with ID {playbook_id} not found."}), 404
    else:
        # If playbook_id is not provided, fetch information about all playbooks
        playbook_data = []
        for playbook in playbooks:
            playbook_info = {
                "id": playbook["id"],
                "name": playbook["name"],
                "description": playbook["description"]
            }
            playbook_data.append(playbook_info)
        return jsonify(playbook_data)

# Execute a playbook given its id
@app.route('/playbooks/<playbook_id>/execute', methods=['POST'])
def execute_playbook_route(playbook_id):
    return execute_playbook(playbook_id)

# Get playbook execution results
@app.route('/playbooks/results', methods=['POST'])
def get_playbook_results_route():
    return get_playbook_results()

# Get all historical alerts
@app.route('/historical_alerts', methods=['GET'])
def get_historical_alerts_route():
    alerts_collection, _ = connect_to_mongodb()
    historical_alerts = list_all_historical_alerts(alerts_collection)
    return jsonify(historical_alerts)

# Get a playbook associated with the alert
@app.route('/playbook/<alert_id>', methods=['GET'])
def get_playbook_for_alert_route(alert_id):
    alerts_collection, _ = connect_to_mongodb()
    historical_alerts = list_all_historical_alerts(alerts_collection)

    playbook_id = None
    for alert in historical_alerts:
        if alert.get('_id') == alert_id:
            playbook_id = alert.get('playbook_id')
            break
    if playbook_id:
        return jsonify({"playbook_id": playbook_id})
    return jsonify({"error": f"No playbook found for alert ID {alert_id}"}), 404

# Encode all historical alerts
@app.route('/encode/historical_alerts', methods=['GET'])
def encode_historical_alerts_route():
    alerts_collection, _ = connect_to_mongodb()
    historical_alerts = list_all_historical_alerts(alerts_collection)
    one_hot_alerts = convert_one_hot_alerts(historical_alerts)
    historical_encoded_alerts = encode_alerts(one_hot_alerts)
    return jsonify({"encoded_alerts": historical_encoded_alerts.tolist()})

# Encode a new alert, which is sent as json in the request body
@app.route('/encode/new_alert_json', methods=['POST'])
def encode_new_alert_json_route():
    new_alert = request.json
    one_hot_alert = convert_one_hot_alert(new_alert)
    new_encoded_alert = encode_alerts(np.array([one_hot_alert]))
    return jsonify({"encoded_alert": new_encoded_alert.tolist()})

# Encode a new alert based on its "_id" in the request body
@app.route('/encode/new_alert_id', methods=['POST'])
def encode_new_alert_id_route():
    alert_id = request.json.get("_id")
    if not alert_id:
        return jsonify({"error": "Alert _id not provided in the request."}), 400

    alerts_collection, _ = connect_to_mongodb()
    new_alert = alerts_collection.find_one({"_id": alert_id})
    if not new_alert:
        return jsonify({"error": "Alert not found."}), 404

    one_hot_alert = convert_one_hot_alert(new_alert)
    new_encoded_alert = encode_alerts(np.array([one_hot_alert]))
    return jsonify({"encoded_alert": new_encoded_alert.tolist()})

# Calculate similarity scores of an alert based on its "_id" in the request body
@app.route('/similarity_scores', methods=['POST'])
def calculate_similarity_route():
    try:
        data = request.json
        alert_id = data.get('_id')
        method = data.get('method')

        if alert_id is None or method is None:
            raise ValueError("Please provide '_id' and 'method' in the request body.")

        # Retrieve the new alert from the database based on its _id
        alerts_collection, _ = connect_to_mongodb()
        new_alert = alerts_collection.find_one({"_id": alert_id})

        if new_alert is None:
            raise ValueError(f"No alert found with _id '{alert_id}'.")

        # Convert and encode the new alert
        one_hot_alert = convert_one_hot_alert(new_alert)
        new_encoded_alert = encode_alerts(np.array([one_hot_alert]))

        # Calculate similarity scores
        historical_alerts = list_all_historical_alerts(alerts_collection)
        one_hot_alerts = convert_one_hot_alerts(historical_alerts)
        historical_encoded_alerts = encode_alerts(one_hot_alerts)
        similarity_scores = calculate_similarity_scores(new_encoded_alert, historical_encoded_alerts, method)

        return jsonify({"similarity_scores": similarity_scores.tolist()})

    except Exception as e:
        return jsonify({"error": str(e)})

# Fetch playbook information using playbook id
def fetch_playbook_info(playbook_id):
    execute_url = f"http://localhost:{PORT}/playbooks?playbook_id={playbook_id}"

    try:
        response = requests.get(execute_url)
        playbook_data = response.json()

        if response.status_code == 200:
            return playbook_data
        else:
            return {"error": f"Failed to retrieve playbook with id {playbook_id}. Status Code: {response.status_code}"}

    except requests.RequestException as e:
        return {"error": f"Request to Shuffle API failed: {str(e)}"}

# Identify top-k most similar alerts and extract corresponding playbooks
@app.route('/top_k_similar_alerts', methods=['POST'])
def identify_top_k_similar_alerts_route():
    try:
        data = request.json
        similarity_scores = data.get('similarity_scores')
        k = data.get('k')

        if similarity_scores is None or k is None:
            raise ValueError("Please provide 'similarity_scores' and 'k' in the request body.")

        # Extract similarity scores from the nested list
        similarity_scores = similarity_scores[0]
        print(similarity_scores)

        # Sort similarity scores in descending order and select top-k indices
        top_k_indices = sorted(range(len(similarity_scores)), key=lambda i: similarity_scores[i], reverse=True)[:k]
        print(top_k_indices)

        # Fetch playbook information for each similar alert
        similar_alerts = []
        alerts_collection, _ = connect_to_mongodb()
        historical_alerts = list_all_historical_alerts(alerts_collection)
        playbook_data_list = []
        for id in top_k_indices:
            alert_id = historical_alerts[id]["_id"]
            playbook_id = get_playbook_id_for_alert(alert_id)
            playbook_data = fetch_playbook_info(playbook_id)
            #print(playbook_data)
            playbook_data_list.append(playbook_data)

        return jsonify({"playbooks": playbook_data_list})

    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    app.run(host=SERVER_IP, port=PORT, debug=True)

"""
Kafka-related API routes.
"""

import logging
import json
from flask import request, jsonify
from api.routes import kafka_bp
from core.analysis_and_reporting.kafka_publisher import KafkaPublisher
from core.alerts_consumer.kafka_consumer import KafkaAlertConsumer
from core.exceptions import ScenarioError, KafkaPublishError, KafkaConsumeError

logger = logging.getLogger(__name__)

_publisher = KafkaPublisher()
_consumer  = KafkaAlertConsumer()


@kafka_bp.route('/publish_alerts', methods=['POST'])
def publish_alerts():
    """Publish alerts to Kafka topic."""
    try:
        data = request.get_json()
        scenario = request.args.get('scenario')
        
        if not scenario:
            return jsonify({'status': 'error', 'message': 'scenario parameter is required'}), 400
        
        if not data:
            return jsonify({'status': 'error', 'message': 'Request body is required'}), 400
        
        _publisher.publish_alert(scenario.lower(), data)
        return jsonify({'status': 'success', 'message': 'Alert published successfully'}), 200
        
    except ScenarioError as e:
        logger.warning(f"Invalid scenario: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error publishing alerts: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@kafka_bp.route('/publish_responses_with_alert_stix', methods=['POST'])
def publish_responses_with_alert_stix():
    """Publish STIX responses with alert to Kafka."""
    try:
        scenario = request.args.get('scenario')
        if not scenario:
            return jsonify({'status': 'error', 'message': 'scenario parameter is required'}), 400
        
        # Get response_body from form data
        response_body = request.form.get('response_body')
        if response_body:
            response_body = json.loads(response_body)
        else:
            return jsonify({"status": "error", "message": "Missing response_body in the request"}), 400
        
        # Handle triaged_alert from either file upload or direct JSON string
        triaged_alert = None
        if 'triaged_alert' in request.files:
            file = request.files['triaged_alert']
            if file:
                try:
                    triaged_alert = json.loads(file.read().decode('utf-8'))
                    logger.debug("Successfully read triaged_alert from file")
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding triaged_alert JSON from file: {e}")
                    return jsonify({"status": "error", "message": f"Invalid JSON in triaged_alert file: {str(e)}"}), 400
        elif 'triaged_alert' in request.form:
            try:
                triaged_alert = json.loads(request.form['triaged_alert'])
                logger.debug("Successfully read triaged_alert from form data")
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding triaged_alert JSON from form data: {e}")
                return jsonify({"status": "error", "message": f"Invalid JSON in triaged_alert form data: {str(e)}"}), 400
        
        if not triaged_alert:
            return jsonify({"status": "error", "message": "No valid triaged_alert provided"}), 400
        
        # Publish STIX response
        _publisher.publish_stix_response(scenario.lower(), response_body, triaged_alert)
        return jsonify({"status": "success", "message": "STIX response sent to Kafka topic successfully"}), 200
        
    except ScenarioError as e:
        logger.warning(f"Invalid scenario: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error publishing STIX response: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@kafka_bp.route('/publish_message_to_hm', methods=['POST'])
def publish_message_to_hm():
    """Publish message to honeypot manager."""
    try:
        message = request.args.get('message')
        if not message:
            return jsonify({'status': 'error', 'message': 'Missing message parameter'}), 400
        
        message = message.lower()
        if message not in ['start', 'stop']:
            return jsonify({'status': 'error', 'message': 'Invalid message parameter, should be either "start" or "stop"'}), 400
        
        scenario = request.args.get('scenario')
        if not scenario:
            scenario = 'sc13'  # Default scenario
        
        _publisher.publish_message_to_honeypot_manager(scenario.lower(), message)
        return jsonify({
            'status': 'success',
            'message': f'Informed Honeypot Manager to {message} calculating a new deceive strategy'
        }), 200
        
    except Exception as e:
        logger.error(f"Error publishing message to HM: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@kafka_bp.route('/consume_alerts', methods=['GET'])
def consume_alerts():
    """Consume alerts from Kafka topic."""
    try:
        scenario = request.args.get('scenario')
        if not scenario:
            return jsonify({'status': 'error', 'message': 'scenario parameter is required'}), 400
        
        message = _consumer.consume_alerts(scenario.lower())
        
        if message:
            return jsonify({'status': 'success', 'message': message}), 200
        else:
            return jsonify({'status': 'error', 'message': 'No messages available'}), 404
            
    except ScenarioError as e:
        logger.warning(f"Invalid scenario: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error consuming alerts: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

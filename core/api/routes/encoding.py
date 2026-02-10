"""
Alert encoding and similarity calculation routes.
"""

import logging
from flask import request, jsonify
from core.api.routes import encoding_bp
from core.services import AlertService
from core.exceptions import AlertNotFoundError

logger = logging.getLogger(__name__)

alert_service = AlertService()


@encoding_bp.route('/encode/historical_alerts', methods=['GET'])
def encode_historical_alerts():
    """Encode all historical alerts."""
    try:
        encoded_alerts = alert_service.encode_historical_alerts()
        return jsonify({"encoded_alerts": encoded_alerts.tolist()}), 200
    except Exception as e:
        logger.error(f"Error encoding historical alerts: {e}")
        return jsonify({"error": str(e)}), 500


@encoding_bp.route('/encode/new_alert_json', methods=['POST'])
def encode_new_alert_json():
    """Encode a new alert sent as JSON in the request body."""
    try:
        new_alert = request.get_json()
        if not new_alert:
            return jsonify({"error": "Request body is required"}), 400
        
        encoded_alert = alert_service.encode_alert(new_alert)
        return jsonify({"encoded_alert": encoded_alert.tolist()}), 200
    except Exception as e:
        logger.error(f"Error encoding new alert: {e}")
        return jsonify({"error": str(e)}), 500


@encoding_bp.route('/encode/new_alert_id', methods=['POST'])
def encode_new_alert_id():
    """Encode a new alert based on its _id in the request body."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        alert_id = data.get("_id")
        if not alert_id:
            return jsonify({"error": "Alert _id not provided in the request"}), 400
        
        alert = alert_service.get_alert_by_id(alert_id)
        encoded_alert = alert_service.encode_alert(alert)
        return jsonify({"encoded_alert": encoded_alert.tolist()}), 200
        
    except AlertNotFoundError:
        return jsonify({"error": "Alert not found"}), 404
    except Exception as e:
        logger.error(f"Error encoding alert by ID: {e}")
        return jsonify({"error": str(e)}), 500


@encoding_bp.route('/similarity_scores', methods=['POST'])
def calculate_similarity():
    """Calculate similarity scores of an alert based on its _id."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        alert_id = data.get('_id')
        method = data.get('method')
        
        if not alert_id or not method:
            return jsonify({"error": "Please provide '_id' and 'method' in the request body"}), 400
        
        similarity_scores = alert_service.calculate_similarity(alert_id, method)
        return jsonify({"similarity_scores": similarity_scores.tolist()}), 200
        
    except AlertNotFoundError:
        return jsonify({"error": f"No alert found with _id '{alert_id}'"}), 404
    except Exception as e:
        logger.error(f"Error calculating similarity: {e}")
        return jsonify({"error": str(e)}), 500


@encoding_bp.route('/top_k_similar_alerts', methods=['POST'])
def identify_top_k_similar_alerts():
    """Identify top-k most similar alerts and extract corresponding playbooks."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        similarity_scores = data.get('similarity_scores')
        k = data.get('k')
        
        if similarity_scores is None or k is None:
            return jsonify({"error": "Please provide 'similarity_scores' and 'k' in the request body"}), 400
        
        playbooks = alert_service.get_top_k_similar_alerts(similarity_scores, k)
        return jsonify({"playbooks": playbooks}), 200
        
    except Exception as e:
        logger.error(f"Error identifying top-k similar alerts: {e}")
        return jsonify({"error": str(e)}), 500

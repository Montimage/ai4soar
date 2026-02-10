"""
Alert-related API routes.
"""

import logging
from flask import request, jsonify
from core.api.routes import alerts_bp
from core.services import WazuhService, AlertService

logger = logging.getLogger(__name__)

wazuh_service = WazuhService()
alert_service = AlertService()


@alerts_bp.route('/fetch_alerts', methods=['GET'])
def fetch_alerts():
    """Retrieve recent Wazuh alerts with specified characteristics."""
    try:
        usecase = request.args.get('usecase')
        if not usecase:
            return jsonify({'error': 'usecase parameter is required'}), 400
        
        alerts = wazuh_service.fetch_alerts(usecase)
        if alerts:
            return jsonify(alerts), 200
        else:
            return jsonify({'error': 'No alerts found or an error occurred'}), 500
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({'error': str(e)}), 500


@alerts_bp.route('/historical_alerts', methods=['GET'])
def get_historical_alerts():
    """Get all historical alerts from database."""
    try:
        historical_alerts = alert_service.get_all_historical_alerts()
        return jsonify(historical_alerts), 200
    except Exception as e:
        logger.error(f"Error getting historical alerts: {e}")
        return jsonify({'error': str(e)}), 500

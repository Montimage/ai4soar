"""
Playbook-related API routes.
"""

import logging
from flask import request, jsonify
from core.api.routes import playbooks_bp
from core.services import PlaybookService, AlertService, CalderaService
from core.exceptions import PlaybookNotFoundError

logger = logging.getLogger(__name__)

playbook_service = PlaybookService()
alert_service = AlertService()
caldera_service = CalderaService()


@playbooks_bp.route('/playbooks', methods=['GET'])
def get_playbooks():
    """List all playbooks or get a specific playbook by ID."""
    try:
        playbook_id = request.args.get('playbook_id')
        
        if playbook_id:
            # Get specific playbook
            try:
                playbook = playbook_service.get_playbook_by_id(playbook_id)
                return jsonify(playbook), 200
            except PlaybookNotFoundError:
                return jsonify({"error": f"Playbook with ID {playbook_id} not found"}), 404
        else:
            # Get all playbooks
            playbooks = playbook_service.get_all_playbooks()
            return jsonify(playbooks), 200
            
    except Exception as e:
        logger.error(f"Error getting playbooks: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbooks/<playbook_id>/execute', methods=['POST'])
def execute_playbook(playbook_id):
    """Execute a playbook by ID."""
    try:
        data = request.get_json() or {}
        result = playbook_service.execute_playbook(playbook_id, data)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error executing playbook: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbooks/results', methods=['POST'])
def get_playbook_results():
    """Get playbook execution results."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        results = playbook_service.get_playbook_results(data)
        return jsonify(results), 200
    except Exception as e:
        logger.error(f"Error getting playbook results: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/playbook/<alert_id>', methods=['GET'])
def get_playbook_for_alert(alert_id):
    """Get playbook associated with an alert."""
    try:
        playbook_id = alert_service.get_playbook_id_for_alert(alert_id)
        
        if playbook_id:
            return jsonify({"playbook_id": playbook_id}), 200
        else:
            return jsonify({"error": f"No playbook found for alert ID {alert_id}"}), 404
            
    except Exception as e:
        logger.error(f"Error getting playbook for alert: {e}")
        return jsonify({'error': str(e)}), 500


@playbooks_bp.route('/execute_ability', methods=['POST'])
def execute_ability():
    """Execute Caldera blue agent ability."""
    try:
        ability_id = request.form.get('ability_id')
        target = request.form.get('target')
        
        # If ability_id is empty and target is not empty, consider it as a no-op
        if ability_id == "" and target != "":
            return jsonify({'message': 'No action taken as ability_id is empty and target is provided.'}), 200
        
        # If both ability_id and target are provided, execute the ability
        if ability_id and target:
            response = caldera_service.execute_ability(ability_id, target)
            return jsonify({
                'message': 'Ability execution initiated successfully',
                'response': response.text
            }), 200
        
        # If not valid inputs, return error
        return jsonify({'error': 'Invalid input - both ability_id and target are required'}), 400
        
    except ValueError as e:
        logger.warning(f"Validation error: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error executing ability: {e}")
        return jsonify({'error': str(e)}), 500

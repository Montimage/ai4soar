"""
Playbook verification routes.
"""

import logging
from flask import request, jsonify
from core.api.routes import verification_bp
from core.playbook_verification.verifier import PlaybookVerifier

logger = logging.getLogger(__name__)


@verification_bp.route('/verify_playbook', methods=['POST'])
def verify_playbook():
    """Verify a playbook for logical contradictions."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No playbook data provided"}), 400
        
        use_local_model = request.args.get('use_local_model', 'false').lower() == 'true'
        verifier = PlaybookVerifier(use_local_model=use_local_model)
        
        verification_result = verifier.verify_playbook(data)
        return jsonify(verification_result), 200
        
    except Exception as e:
        logger.error(f"Error verifying playbook: {e}")
        return jsonify({"error": str(e)}), 500

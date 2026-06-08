"""
Playbook verification routes.

POST /verify_playbook
  Accepts three formats (auto-detected):
    - CACAO 2.0 JSON    (has 'spec_version' or 'workflow' key)
    - Shuffle JSON      (has 'actions' key)
    - Internal nodes    (has 'nodes' key)

  Query params:
    structural_only=true   skip LLM semantic check (faster, no API key needed)
    is_template=true       skip {{placeholder}} warnings (library templates)
"""

import logging
from flask import request, jsonify
from api.routes import verification_bp
from core.playbook_verification.verifier import PlaybookVerifier

logger = logging.getLogger(__name__)


@verification_bp.route('/verify_playbook', methods=['POST'])
def verify_playbook():
    """Verify a CACAO 2.0, Shuffle, or internal-format playbook."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No playbook data provided"}), 400

        structural_only = request.args.get('structural_only', 'false').lower() == 'true'
        is_template     = request.args.get('is_template', 'false').lower() == 'true'

        verifier = PlaybookVerifier()
        result   = verifier.verify(data, structural_only=structural_only, is_template=is_template)
        return jsonify(result), 200

    except Exception as exc:
        logger.error(f"Error verifying playbook: {exc}")
        return jsonify({"error": str(exc)}), 500

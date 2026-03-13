"""
Playbook recommendation routes — MITRE ATT&CK STIX-based.
"""

import logging
from flask import request, jsonify
from core.api.routes import recommendations_bp
from core.services.recommendation_service import RecommendationService

logger = logging.getLogger(__name__)

_recommendation_service = RecommendationService()


@recommendations_bp.route('/recommend', methods=['POST'])
def recommend_playbooks():
    """
    Recommend playbooks for a given Wazuh alert.

    Request body:
        {
            "alert": { <full Wazuh ES document> },
            "k": 5   (optional, default 5)
        }

    Response:
        {
            "source": "stix_direct" | "similarity_fallback" | "no_data",
            "confidence": 1.0,
            "technique_ids": ["T1110.001", "T1021.004"],
            "technique_names": ["Password Guessing", "SSH"],
            "tactics": ["Credential Access", "Lateral Movement"],
            "playbook_count": 4,
            "playbooks": [
                {"id": "M1036", "name": "Account Lockout Policy", "description": "..."},
                ...
            ]
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        alert = data.get("alert")
        if not alert:
            return jsonify({"error": "'alert' field is required"}), 400

        k = data.get("k", 5)
        result = _recommendation_service.recommend(alert, k=k)
        return jsonify(result.to_dict()), 200

    except Exception as e:
        logger.error(f"Error recommending playbooks: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/technique/<technique_id>/playbooks', methods=['GET'])
def get_playbooks_for_technique(technique_id: str):
    """
    Return all mitigations (playbook names) for a MITRE technique ID.

    Example: GET /api/mitre/technique/T1110.001/playbooks
    """
    try:
        kb = _recommendation_service._kb
        playbooks = kb.get_playbooks_for_technique(technique_id)
        technique = kb.get_technique_info(technique_id)
        return jsonify({
            "technique_id": technique_id,
            "technique_name": technique["name"] if technique else None,
            "playbook_count": len(playbooks),
            "playbooks": playbooks,
        }), 200
    except Exception as e:
        logger.error(f"Error fetching playbooks for technique {technique_id}: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/techniques', methods=['GET'])
def list_techniques_with_playbooks():
    """
    List all MITRE techniques that have at least one mitigation (playbook).

    Query params:
        tactic: filter by tactic name (optional), e.g. ?tactic=Credential+Access
    """
    try:
        kb = _recommendation_service._kb
        kb.load()
        tactic_filter = request.args.get("tactic", "").lower()

        results = []
        for tech_id, mitigations in kb._tech_to_mitigations.items():
            tech = kb.get_technique_info(tech_id)
            if not tech:
                continue
            if tactic_filter and tactic_filter not in [t.lower() for t in tech["tactics"]]:
                continue
            results.append({
                "technique_id": tech_id,
                "technique_name": tech["name"],
                "tactics": tech["tactics"],
                "playbook_count": len(mitigations),
            })

        results.sort(key=lambda x: x["technique_id"])
        return jsonify({
            "total": len(results),
            "techniques": results,
        }), 200

    except Exception as e:
        logger.error(f"Error listing techniques: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/kb/stats', methods=['GET'])
def kb_stats():
    """Return statistics about the loaded STIX knowledge base."""
    try:
        stats = _recommendation_service.get_kb_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error fetching KB stats: {e}")
        return jsonify({"error": str(e)}), 500

"""
Playbook recommendation routes — 3-stage MITRE ATT&CK / LLM / CACAO engine.
"""

import logging
import os

from flask import jsonify, request

from api.routes import recommendations_bp
from core.config import config
from core.intelligent_orchestration.enrichment.pipeline import EnrichmentPipeline
from core.intelligent_orchestration.orchestrator import PlaybookOrchestrator

logger = logging.getLogger(__name__)

_pipeline     = EnrichmentPipeline()
_orchestrator = PlaybookOrchestrator()


@recommendations_bp.route('/recommend', methods=['POST'])
def recommend_playbooks():
    """
    Recommend playbooks for any alert using the 3-stage cascade.

    Request body:
        {
            "alert": { <full alert — Wazuh ES, ECS, Sigma, or plain JSON> },
            "k":     5   (optional, default 5)
        }

    Response:
        {
            "source":                 "stix_direct" | "llm_attribution" | "fused"
                                      | "similarity_model" | "cacao_generated" | "none",
            "confidence":             0.92,
            "confidence_tier":        "HIGH" | "MEDIUM" | "LOW",
            "paths_used":             ["B", "C"],
            "auto_executable":        false,
            "requires_human_approval": true,
            "requires_human_review":  false,
            "technique_ids":          ["T1110.001"],
            "technique_names":        ["Brute Force: Password Guessing"],
            "tactics":                ["credential-access"],
            "llm_reasoning":          "...",
            "playbook_count":         3,
            "playbooks":              [ {"id": "M1036", "name": "..."}, ... ],
            "cacao_playbook":         { ... }   (Path D only, else null)
        }

    Stage routing:
        Stage 1 — alert has MITRE tag + Path A confidence ≥ early_exit_threshold
                  → paths_used=["A"], HIGH tier, auto_executable=true
        Stage 2 — Path B (LLM) + Path C (ML) run in parallel, results fused
                  → paths_used=["B"], ["C"], or ["B","C"]
        Stage 3 — safety net: LLM generates a CACAO 2.0 playbook
                  → paths_used=["D"], LOW tier, requires_human_review=true
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        alert = data.get("alert")
        if not alert:
            return jsonify({"error": "'alert' field is required"}), 400

        k        = int(data.get("k", 5))
        enriched = _pipeline.enrich(alert)
        result   = _orchestrator.orchestrate(enriched, k=k)

        payload = result.to_dict()
        payload["playbook_count"] = len(payload["playbooks"])
        # Backward-compat alias so old clients keep working
        payload["review_required"] = result.requires_human_review or result.requires_human_approval

        return jsonify(payload), 200

    except Exception as e:
        logger.error(f"Error recommending playbooks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/technique/<technique_id>/playbooks', methods=['GET'])
def get_playbooks_for_technique(technique_id: str):
    """
    Return all STIX mitigations for a MITRE technique ID.

    Example: GET /api/mitre/technique/T1110.001/playbooks
    """
    try:
        kb        = _orchestrator._kb
        playbooks = kb.get_playbooks_for_technique(technique_id)
        technique = kb.get_technique_info(technique_id)
        return jsonify({
            "technique_id":   technique_id,
            "technique_name": technique["name"] if technique else None,
            "playbook_count": len(playbooks),
            "playbooks":      playbooks,
        }), 200
    except Exception as e:
        logger.error(f"Error fetching playbooks for technique {technique_id}: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/techniques', methods=['GET'])
def list_techniques_with_playbooks():
    """
    List all MITRE techniques that have at least one mitigation.

    Query params:
        tactic: filter by tactic name (optional), e.g. ?tactic=credential-access
    """
    try:
        kb = _orchestrator._kb
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
                "technique_id":   tech_id,
                "technique_name": tech["name"],
                "tactics":        tech["tactics"],
                "playbook_count": len(mitigations),
            })

        results.sort(key=lambda x: x["technique_id"])
        return jsonify({"total": len(results), "techniques": results}), 200

    except Exception as e:
        logger.error(f"Error listing techniques: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/kb/stats', methods=['GET'])
def kb_stats():
    """Return statistics about the loaded STIX knowledge base."""
    try:
        stats = _orchestrator._kb.stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error fetching KB stats: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/recommend/paths', methods=['GET'])
def describe_paths():
    """
    Describe the 3-stage recommendation pipeline: status, latency, thresholds.
    Useful for operator dashboards.
    """
    llm_configured = bool(config.llm.openai_api_key or config.llm.anthropic_api_key)
    ml_model_path  = {
        "knn":     config.model.knn_path,
        "lr":      config.model.lr_path,
        "ovr_lr":  config.model.ovr_lr_path,
        "ovr_svm": config.model.ovr_svm_path,
        "xgb":     config.model.xgb_path,
    }.get(config.model.active_model, config.model.knn_path)
    ml_ready = (
        os.path.exists(ml_model_path)
        and os.path.exists(config.model.feature_engineer_path)
    )

    return jsonify({
        "thresholds": {
            "early_exit":     config.orchestration.early_exit_threshold,
            "low_confidence": config.orchestration.low_confidence_threshold,
            "path_c_discount":     config.orchestration.path_c_discount,
            "confirmation_bonus":  config.orchestration.confirmation_bonus,
        },
        "stages": [
            {
                "stage": 1,
                "paths": ["A"],
                "name": "STIX Direct Lookup",
                "description": "Deterministic STIX mitigation lookup for alerts with MITRE tags.",
                "latency": "< 5 ms",
                "confidence_tier": "HIGH",
                "status": "always_available",
            },
            {
                "stage": 2,
                "paths": ["B", "C"],
                "name": "Parallel Attribution + Fusion",
                "description": (
                    "Path B (LLM technique attribution) and Path C (ML tactic similarity) "
                    "run concurrently; results are fused by the Decision Engine."
                ),
                "latency": "1–5 s (gated by Path B LLM call)",
                "path_b": {
                    "status":              "available" if llm_configured else "unavailable — set OPENAI_API_KEY or ANTHROPIC_API_KEY",
                    "model":               config.llm.anthropic_model if config.llm.anthropic_api_key else config.llm.model,
                    "confidence_threshold": config.llm.technique_confidence_threshold,
                },
                "path_c": {
                    "status":       "available" if ml_ready else "unavailable — train model first",
                    "active_model": config.model.active_model.upper(),
                },
            },
            {
                "stage": 3,
                "paths": ["D"],
                "name": "LLM CACAO 2.0 Generation",
                "description": "Safety net: LLM generates a structured CACAO 2.0 incident-response playbook.",
                "latency": "2–10 s",
                "confidence_tier": "LOW — always requires human review",
                "output_format": "OASIS CACAO 2.0",
                "status": "available" if llm_configured else "unavailable — set OPENAI_API_KEY or ANTHROPIC_API_KEY",
            },
        ],
    }), 200

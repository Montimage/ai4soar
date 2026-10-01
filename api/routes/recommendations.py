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
from core.intelligent_orchestration.stix_knowledge_base import STIXKnowledgeBase
from core.exceptions import LLMUnavailableError
from core.playbook_library.loader import PlaybookLibrary
from utils.llm.attribution import load_vocab, technique_name
from utils.llm.client import attribution_spec

logger = logging.getLogger(__name__)

_pipeline     = EnrichmentPipeline()
_orchestrator = PlaybookOrchestrator()
_kb           = STIXKnowledgeBase(config.stix.data_path)
_library      = PlaybookLibrary(config.playbook_library.path)


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
            "ranked_technique_ids":   ["T1110.001", "T1110.003", "T1078"],
                                      # Path B only: the model's full ranked top-k,
                                      # including candidates with no library template
            "ranked_technique_names": ["Password Guessing", "Password Spraying",
                                       "Valid Accounts"],
            "ranked_technique_covered": [true, true, false],
                                      # per ranked id: does the library hold ANY template
                                      # for it (true but absent from technique_ids = its
                                      # template was already supplied by a higher rank)
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
        # Names for Path B's full ranking, including the candidates that resolved to no
        # playbook: the UI shows them, and the static JS name map covers only a third of
        # the 697-technique attribution vocabulary.
        payload["ranked_technique_names"] = [
            technique_name(t) for t in payload.get("ranked_technique_ids", [])
        ]
        # Whether the LIBRARY covers each ranked technique at all. Distinct from
        # technique_ids, which lists only the techniques that contributed a NEW playbook:
        # when two ranked techniques share one template (T1498 and T1499 are both on
        # pb-t1499-block-dos-source), the lower-ranked one is deduplicated away and would
        # otherwise be indistinguishable from a genuine coverage gap.
        payload["ranked_technique_covered"] = [
            bool(_library.get_for_technique(t))
            for t in payload.get("ranked_technique_ids", [])
        ]
        # Backward-compat alias so old clients keep working
        payload["review_required"] = result.requires_human_review or result.requires_human_approval

        return jsonify(payload), 200

    except Exception as e:
        logger.error(f"Error recommending playbooks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/technique/<technique_id>/playbooks', methods=['GET'])
def get_playbooks_for_technique(technique_id: str):
    """
    Return all library playbooks that cover a MITRE technique ID.

    Example: GET /api/mitre/technique/T1110.001/playbooks
    """
    try:
        templates = _library.get_for_technique(technique_id)
        technique = _kb.get_technique_info(technique_id)
        return jsonify({
            "technique_id":   technique_id,
            "technique_name": technique["name"] if technique else None,
            "playbook_count": len(templates),
            "playbooks": [
                {"id": t["id"], "name": t.get("name", t["id"]), "techniques": t.get("techniques", [])}
                for t in templates
            ],
        }), 200
    except Exception as e:
        logger.error(f"Error fetching playbooks for technique {technique_id}: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/techniques', methods=['GET'])
def list_techniques_with_playbooks():
    """
    List all MITRE techniques that have at least one library playbook.

    Query params:
        tactic: filter by tactic name (optional), e.g. ?tactic=credential-access
    """
    try:
        _library.load()
        tactic_filter = request.args.get("tactic", "").lower()

        results = []
        for tech_id, templates in _library._by_technique.items():
            technique = _kb.get_technique_info(tech_id)
            tactics = technique["tactics"] if technique else []
            if tactic_filter and tactic_filter not in [t.lower() for t in tactics]:
                continue
            results.append({
                "technique_id":   tech_id,
                "technique_name": technique["name"] if technique else tech_id,
                "tactics":        tactics,
                "playbook_count": len(templates),
            })

        results.sort(key=lambda x: x["technique_id"])
        return jsonify({"total": len(results), "techniques": results}), 200

    except Exception as e:
        logger.error(f"Error listing techniques: {e}")
        return jsonify({"error": str(e)}), 500


@recommendations_bp.route('/mitre/kb/stats', methods=['GET'])
def kb_stats():
    """Return statistics about the loaded STIX knowledge base and playbook library."""
    try:
        stats = _kb.stats()
        stats.update(_library.stats())
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
    # Resolve Path B exactly as the recommender does (utils/llm/client.attribution_spec),
    # so a local Ollama deployment is not reported as "unavailable" and the model name
    # shown is the one that will actually be called.
    try:
        spec           = attribution_spec()
        llm_configured = True
    except LLMUnavailableError:
        spec           = None
        llm_configured = False

    ml_model_path  = {
        "knn":     config.model.knn_path,
        "lr":      config.model.lr_path,
        "ovr_lr":  config.model.ovr_lr_path,
        "ovr_svm": config.model.ovr_svm_path,
        "rf":      config.model.rf_path,
        "mlp":     config.model.mlp_path,
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
                    "status":   "available" if llm_configured else (
                        "unavailable — set OPENAI_API_KEY or ANTHROPIC_API_KEY, "
                        "or LLM_PROVIDER=ollama"),
                    "provider": spec["provider"] if spec else None,
                    "model":    spec["model"] if spec else None,
                    "confidence_threshold": config.llm.technique_confidence_threshold,
                    # Attribution settings — the knobs that decide accuracy; num_ctx
                    # matters for Ollama, which silently truncates the vocabulary.
                    "vocab":            config.llm.attribution_vocab,
                    "vocab_size":       len(load_vocab(config.llm.attribution_vocab)[0]),
                    "top_k":            config.llm.attribution_top_k,
                    "ranked_k":         config.llm.attribution_ranked_k,
                    "max_tokens":       spec["max_tokens"] if spec else None,
                    "num_ctx":          spec["num_ctx"] if spec and spec["provider"] == "ollama" else None,
                },
                "path_c": {
                    "status": (
                        "disabled — ORCH_PATH_C_ENABLED=false"
                        if not config.orchestration.path_c_enabled
                        else "available" if ml_ready
                        else "unavailable — train model first"
                    ),
                    "enabled":      config.orchestration.path_c_enabled,
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
                "status": "available" if llm_configured else (
                    "unavailable — set OPENAI_API_KEY or ANTHROPIC_API_KEY, "
                    "or LLM_PROVIDER=ollama"),
            },
        ],
    }), 200

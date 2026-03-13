"""
Playbook recommendation service for AI4SOAR.

Two-path recommendation engine:

  Path A — STIX direct lookup (preferred, confidence = 1.0):
    Triggered when alert carries rule.mitre.id (e.g. Wazuh-tagged alerts).
    Technique IDs → STIX knowledge base → mitigation names (playbooks).
    Deterministic. No training required.

  Path B — Similarity learning (fallback, confidence = model probability):
    Triggered when no MITRE tags are present.
    Normalizes the alert to a format-agnostic representation, extracts
    TF-IDF + structured features, and predicts the ATT&CK TACTIC using a
    pre-trained KNN or Logistic Regression classifier (trained on OTRF data).
    Predicted tactic → STIX KB → all mitigations for that tactic.

    The model is trained on OTRF Security-Datasets (Windows event logs +
    Zeek network logs) but generalizes to any alert format because features
    are semantic (log text + behavioral flags), not format-specific.
    Requires: python3 scripts/build_otrf_dataset.py && python3 scripts/train_similarity_model.py
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from core.config import config
from core.exceptions import AlertError
from core.intelligent_orchestration.stix_knowledge_base import (
    STIXKnowledgeBase,
    extract_mitre_ids,
    extract_mitre_technique_names,
    extract_mitre_tactics,
)
from core.intelligent_orchestration.normalizer import auto_normalize
from core.intelligent_orchestration.feature_engineer import AlertFeatureEngineer
from core.intelligent_orchestration.playbook_registry import get_playbooks_for_tactic

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RecommendationResult:
    """Unified result returned by both Path A and Path B."""
    playbooks: List[Dict]        # [{id, name, description}, ...]
    source: str                  # "stix_direct" | "similarity_model" | "no_model" | "no_data"
    confidence: float            # 1.0 for Path A; model probability for Path B
    technique_ids: List[str]     # filled by Path A
    technique_names: List[str]   # filled by Path A
    tactics: List[str]           # alert's explicit tactics (Path A) or predicted (Path B)
    predicted_tactic: str = ""   # Path B: tactic predicted by the model

    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "confidence": round(self.confidence, 4),
            "technique_ids": self.technique_ids,
            "technique_names": self.technique_names,
            "tactics": self.tactics,
            "predicted_tactic": self.predicted_tactic,
            "playbook_count": len(self.playbooks),
            "playbooks": self.playbooks,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class RecommendationService:
    """
    Orchestrates playbook recommendations for incoming alerts.

    The service is stateless between requests. Models are loaded lazily
    on first use and cached in memory for the process lifetime.
    """

    def __init__(self):
        self._kb = STIXKnowledgeBase(config.stix.data_path)
        self._model: Optional[object] = None
        self._fe: Optional[AlertFeatureEngineer] = None
        self._mlb: Optional[object] = None   # MultiLabelBinarizer for OvR models
        self._le:  Optional[object] = None   # LabelEncoder for XGBoost
        self._model_loaded = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def recommend(self, alert: Dict[str, Any], k: int = 5) -> RecommendationResult:
        """
        Return playbook recommendations for any Wazuh/OTRF/generic alert.

        Args:
            alert:  Full alert dict (Wazuh ES doc, OTRF event, or any JSON)
            k:      Maximum number of playbooks to return

        Returns:
            RecommendationResult with playbooks + provenance metadata
        """
        technique_ids   = extract_mitre_ids(alert)
        technique_names = extract_mitre_technique_names(alert)
        tactics         = extract_mitre_tactics(alert)

        if technique_ids:
            return self._path_a(alert, technique_ids, technique_names, tactics, k)
        return self._path_b(alert, technique_names, tactics, k)

    def get_kb_stats(self) -> Dict:
        return self._kb.stats()

    # ------------------------------------------------------------------
    # Path A — STIX direct
    # ------------------------------------------------------------------

    def _path_a(
        self,
        alert: Dict,
        technique_ids: List[str],
        technique_names: List[str],
        tactics: List[str],
        k: int,
    ) -> RecommendationResult:
        playbooks = self._kb.get_playbooks_for_alert(alert)[:k]
        logger.info(
            f"[Path A] {technique_ids} → {len(playbooks)} playbooks"
        )
        return RecommendationResult(
            playbooks=playbooks,
            source="stix_direct",
            confidence=1.0,
            technique_ids=technique_ids,
            technique_names=technique_names,
            tactics=tactics,
        )

    # ------------------------------------------------------------------
    # Path B — similarity model
    # ------------------------------------------------------------------

    def _path_b(
        self,
        alert: Dict,
        technique_names: List[str],
        tactics: List[str],
        k: int,
    ) -> RecommendationResult:
        """
        Normalize → extract features → predict tactic → STIX playbooks.
        Falls back to registry defaults if the model isn't trained yet.
        """
        # 1. Try loading pre-trained model
        if not self._model_loaded:
            self._load_model()

        if self._model is None or self._fe is None:
            # Model not available yet — tell the user what to do
            logger.warning(
                "[Path B] No trained model found. "
                "Run: python3 scripts/build_otrf_dataset.py && "
                "python3 scripts/train_similarity_model.py"
            )
            return RecommendationResult(
                playbooks=[],
                source="no_model",
                confidence=0.0,
                technique_ids=[],
                technique_names=technique_names,
                tactics=tactics,
                predicted_tactic="",
            )

        try:
            # 2. Normalize to format-agnostic schema
            normalized = auto_normalize(alert)

            # 3. Feature extraction
            X = self._fe.transform([normalized])

            # 4. Predict tactic with probability
            # Class list differs per model type:
            #   XGBoost  → LabelEncoder.classes_
            #   OvR      → MultiLabelBinarizer.classes_
            #   KNN/LR   → model.classes_
            proba = self._model.predict_proba(X)[0]
            if self._le is not None:
                classes = np.array(self._le.classes_)
            elif self._mlb is not None:
                classes = np.array(self._mlb.classes_)
            else:
                classes = np.array(self._model.classes_)
            top_idx = int(np.argmax(proba))
            predicted_tactic = classes[top_idx]
            confidence = float(proba[top_idx])

            # 5. Get playbooks: STIX mitigations for predicted tactic (union)
            playbooks = self._get_playbooks_for_tactic_via_stix(predicted_tactic)
            if not playbooks:
                # Registry fallback
                playbooks = get_playbooks_for_tactic(predicted_tactic)
            playbooks = playbooks[:k]

            logger.info(
                f"[Path B] format={normalized.source_format} "
                f"event_type={normalized.event_type} "
                f"→ tactic={predicted_tactic} (conf={confidence:.2f}) "
                f"→ {len(playbooks)} playbooks"
            )
            return RecommendationResult(
                playbooks=playbooks,
                source="similarity_model",
                confidence=confidence,
                technique_ids=[],
                technique_names=technique_names,
                tactics=[predicted_tactic],
                predicted_tactic=predicted_tactic,
            )

        except Exception as e:
            logger.error(f"[Path B] failed: {e}", exc_info=True)
            return RecommendationResult(
                playbooks=[],
                source="no_data",
                confidence=0.0,
                technique_ids=[],
                technique_names=technique_names,
                tactics=tactics,
                predicted_tactic="",
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Lazy-load the trained model and feature engineer from disk."""
        active  = config.model.active_model
        fe_path = config.model.feature_engineer_path

        _path_map = {
            "knn":     config.model.knn_path,
            "lr":      config.model.lr_path,
            "ovr_lr":  config.model.ovr_lr_path,
            "ovr_svm": config.model.ovr_svm_path,
            "xgb":     config.model.xgb_path,
        }
        model_path = _path_map.get(active, config.model.knn_path)

        if not os.path.exists(model_path) or not os.path.exists(fe_path):
            logger.warning(
                f"[Path B] Model files not found at {model_path} / {fe_path}. "
                "Train the model first."
            )
            self._model_loaded = True
            return

        try:
            self._model = joblib.load(model_path)
            self._fe    = AlertFeatureEngineer.load(fe_path)
            if active in ("ovr_lr", "ovr_svm"):
                mlb_path = config.model.label_binarizer_path
                if os.path.exists(mlb_path):
                    self._mlb = joblib.load(mlb_path)
            elif active == "xgb":
                le_path = config.model.label_encoder_path
                if os.path.exists(le_path):
                    self._le = joblib.load(le_path)
            logger.info(
                f"[Path B] Loaded {active.upper()} model from {model_path}"
            )
        except Exception as e:
            logger.error(f"[Path B] Failed to load model: {e}")
        finally:
            self._model_loaded = True

    def _get_playbooks_for_tactic_via_stix(self, tactic: str) -> List[Dict]:
        """
        Return deduplicated mitigations for ALL techniques belonging to a tactic.
        Sorted by frequency (mitigations shared by more techniques = more universal).
        Falls back to registry if STIX KB is unavailable.
        """
        try:
            self._kb.load()
        except FileNotFoundError:
            logger.debug("STIX KB unavailable — using registry fallback for tactic playbooks")
            return get_playbooks_for_tactic(tactic)

        freq: Dict[str, int] = {}
        mitigation_index: Dict[str, Dict] = {}

        for tech_id, tech_info in self._kb._techniques.items():
            if tactic not in tech_info.get("tactics", []):
                continue
            for m in self._kb.get_playbooks_for_technique(tech_id):
                mid = m["id"]
                freq[mid] = freq.get(mid, 0) + 1
                mitigation_index[mid] = m

        sorted_ids = sorted(freq, key=lambda x: -freq[x])
        result = [mitigation_index[mid] for mid in sorted_ids]
        # fallback if STIX has nothing for this tactic
        return result if result else get_playbooks_for_tactic(tactic)

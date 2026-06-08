"""
Path C — ML-based Technique Classification.

Input:  EnrichedAlert
Output: Optional[PathResult] — None if model not trained or no playbooks found

Approach: supervised multi-class classification.
  - Features: TF-IDF of alert text (150-dim) + 17 structured features (severity,
    event type, network context) = 167-dim feature vector.
  - Models: KNN (cosine retrieval), LR, RF, MLP (sklearn), OvR variants, XGBoost.
  - Labels: MITRE T-codes (trained with --target technique, default) or
    ATT&CK tactic phases (legacy, --target tactic).

The predicted class type is detected automatically at inference time:
  - T-code (e.g. "T1021.002") → get_for_technique() → technique-specific CACAO
  - Tactic (e.g. "lateral-movement") → get_for_tactic() → broader CACAO

T-code models match Path A/B precision and carry no confidence discount in fusion.
"""

import logging
import os
import re
from typing import Dict, List, Optional

import joblib
import numpy as np

_TCODE_RE = re.compile(r"^T\d{4}")

from core.config import config
from core.intelligent_orchestration.enrichment.enriched_alert import EnrichedAlert
from core.intelligent_orchestration.enrichment.ioc_extractor import IOCExtractor
from core.intelligent_orchestration.feature_engineer import AlertFeatureEngineer
from core.intelligent_orchestration.normalizer import auto_normalize
from core.intelligent_orchestration.parameterizer import PlaybookParameterizer
from core.intelligent_orchestration.path_result import PathResult
from core.playbook_library.loader import PlaybookLibrary

logger = logging.getLogger(__name__)


class PathCRecommender:

    def __init__(
        self,
        library:       PlaybookLibrary,
        ioc_extractor: IOCExtractor,
        parameterizer: PlaybookParameterizer,
    ) -> None:
        self._library       = library
        self._ioc_extractor = ioc_extractor
        self._parameterizer = parameterizer
        self._model         = None
        self._fe: Optional[AlertFeatureEngineer] = None
        self._mlb           = None
        self._le            = None
        self._model_loaded  = False

    def run(self, enriched: EnrichedAlert, k: int) -> Optional[PathResult]:
        """
        Normalize → features → predict tactic → library playbooks.
        Returns None to fall through to Path D via the Orchestrator.
        """
        if not self._model_loaded:
            self._load_model()

        if self._model is None or self._fe is None:
            logger.info("[Path C] No trained model — returning None")
            return None

        try:
            normalized = auto_normalize(enriched.raw)
            X          = self._fe.transform([normalized])
            proba      = self._model.predict_proba(X)[0]

            if self._le is not None:
                classes = np.array(self._le.classes_)
            elif self._mlb is not None:
                classes = np.array(self._mlb.classes_)
            else:
                classes = np.array(self._model.classes_)

            top_idx    = int(np.argmax(proba))
            predicted  = classes[top_idx]
            confidence = float(proba[top_idx])

            iocs      = self._ioc_extractor.extract(enriched.raw)
            playbooks: List[Dict] = []
            seen: set = set()

            is_tcode = bool(_TCODE_RE.match(predicted))
            if is_tcode:
                templates = self._library.get_for_technique(predicted)
            else:
                templates = self._library.get_for_tactic(predicted)

            for template in templates:
                if template["id"] not in seen:
                    seen.add(template["id"])
                    pb = self._parameterizer.parameterize(template, iocs, enriched.raw)
                    playbooks.append(pb.to_dict())

            playbooks = playbooks[:k]

            if not playbooks:
                label = f"technique={predicted}" if is_tcode else f"tactic={predicted}"
                logger.info(f"[Path C] {label} → no library templates")
                return None

            logger.info(
                f"[Path C] {normalized.source_format}/{normalized.event_type} "
                f"→ {'technique' if is_tcode else 'tactic'}={predicted} "
                f"(conf={confidence:.2f}) → {len(playbooks)} CACAO playbooks"
            )
            return PathResult(
                playbooks=playbooks,
                source="ml_classifier",
                confidence=confidence,
                technique_names=enriched.technique_names,
                technique_ids=[predicted] if is_tcode else [],
                tactics=[] if is_tcode else [predicted],
                predicted_tactic="" if is_tcode else predicted,
            )

        except Exception as exc:
            logger.error(f"[Path C] inference failed: {exc}", exc_info=True)
            return None

    def _load_model(self) -> None:
        active    = config.model.active_model
        fe_path   = config.model.feature_engineer_path
        path_map  = {
            "knn":     config.model.knn_path,
            "lr":      config.model.lr_path,
            "ovr_lr":  config.model.ovr_lr_path,
            "ovr_svm": config.model.ovr_svm_path,
            "rf":      config.model.rf_path,
            "mlp":     config.model.mlp_path,
            "xgb":     config.model.xgb_path,
        }
        model_path = path_map.get(active, config.model.knn_path)

        if not os.path.exists(model_path) or not os.path.exists(fe_path):
            logger.info(f"[Path C] Model not found at {model_path}. Train first.")
            self._model_loaded = True
            return

        try:
            self._model = joblib.load(model_path)
            self._fe    = AlertFeatureEngineer.load(fe_path)
            if active in ("ovr_lr", "ovr_svm"):
                if os.path.exists(config.model.label_binarizer_path):
                    self._mlb = joblib.load(config.model.label_binarizer_path)
            elif active == "xgb":
                if os.path.exists(config.model.label_encoder_path):
                    self._le  = joblib.load(config.model.label_encoder_path)
            # knn / lr / rf / mlp all expose .classes_ directly — no extra artifacts
            logger.info(f"[Path C] Loaded {active.upper()} model from {model_path}")
        except Exception as exc:
            logger.error(f"[Path C] Failed to load model: {exc}")
        finally:
            self._model_loaded = True

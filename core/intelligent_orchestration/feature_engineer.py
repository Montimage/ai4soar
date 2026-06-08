"""
Alert feature engineering for AI4SOAR Path B (similarity learning).

Converts NormalizedAlert → fixed-length numpy feature vector combining:
  - TF-IDF of raw_text  (captures attack semantics, generalizes across formats)
  - Structured features (severity, network context, event type, presence flags)

The TF-IDF vocabulary is fitted on TRAINING data only (never test/inference data)
to prevent data leakage and ensure generalization to new alerts.

Serialized with joblib for use in production inference.
"""

import logging
import os
from typing import List

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from core.intelligent_orchestration.normalizer import NormalizedAlert

logger = logging.getLogger(__name__)

# Structured feature names — fixed order, used for interpretability
STRUCT_FEATURES = [
    "severity",
    "src_is_private",
    "dst_is_private",
    "has_user",
    "has_network",
    "has_process",
    "port_well_known",
    "port_registered",
    "port_ephemeral",
    "port_unknown",
    "type_auth",
    "type_network",
    "type_process",
    "type_file",
    "type_lateral",
    "type_discovery",
    "type_unknown",
]


class AlertFeatureEngineer:
    """
    Fits and transforms NormalizedAlert objects → numpy feature vectors.

    Usage:
        fe = AlertFeatureEngineer()
        X_train = fe.fit_transform(train_alerts)   # fit once on training data
        X_test  = fe.transform(test_alerts)         # reuse fitted vocabulary

        fe.save("models/feature_engineer.joblib")
        fe2 = AlertFeatureEngineer.load("models/feature_engineer.joblib")
        X_new = fe2.transform([new_alert])
    """

    def __init__(self, n_tfidf: int = 150):
        self.n_tfidf = n_tfidf
        self._actual_tfidf_dim: int = n_tfidf  # updated after fit() with real vocab size
        self.tfidf = TfidfVectorizer(
            max_features=n_tfidf,
            ngram_range=(1, 2),       # unigrams + bigrams
            min_df=1,                 # include all terms; IDF naturally downweights rare ones
            sublinear_tf=True,        # log(1+tf) — dampens high-freq terms
            strip_accents="unicode",
            analyzer="word",
            token_pattern=r"[a-zA-Z0-9_\-\.]{2,}",  # include hyphens/dots
            stop_words=None,          # keep all — "failed", "access" are meaningful
        )
        self._fitted = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fit(self, alerts: List[NormalizedAlert]) -> "AlertFeatureEngineer":
        texts = [a.raw_text for a in alerts]
        self.tfidf.fit(texts)
        self._actual_tfidf_dim = len(self.tfidf.vocabulary_)
        self._fitted = True
        logger.info(
            f"TF-IDF fitted: {len(texts)} docs, "
            f"vocab={self._actual_tfidf_dim} terms, "
            f"dim={self.feature_dim}"
        )
        return self

    def transform(self, alerts: List[NormalizedAlert]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("Call fit() or load a saved engineer before transform()")
        texts = [a.raw_text for a in alerts]
        tfidf_dense = self.tfidf.transform(texts).toarray().astype(np.float32)
        struct_mat = np.array(
            [_struct_vec(a) for a in alerts], dtype=np.float32
        )
        return np.hstack([tfidf_dense, struct_mat])

    def fit_transform(self, alerts: List[NormalizedAlert]) -> np.ndarray:
        return self.fit(alerts).transform(alerts)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        joblib.dump(self, path)
        logger.info(f"Feature engineer saved → {path}")

    @staticmethod
    def load(path: str) -> "AlertFeatureEngineer":
        fe = joblib.load(path)
        logger.info(f"Feature engineer loaded ← {path} (dim={fe.feature_dim})")
        return fe

    @property
    def feature_dim(self) -> int:
        # Backward compat: objects saved before _actual_tfidf_dim was added
        dim = getattr(self, "_actual_tfidf_dim", self.n_tfidf)
        return dim + len(STRUCT_FEATURES)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _struct_vec(a: NormalizedAlert) -> List[float]:
    p = a.src_port_range
    t = a.event_type
    return [
        a.severity,
        float(a.src_is_private),
        float(a.dst_is_private),
        float(a.has_user),
        float(a.has_network),
        float(a.has_process),
        float(p == "well-known"),
        float(p == "registered"),
        float(p == "ephemeral"),
        float(p == "unknown"),
        float(t == "auth"),
        float(t == "network"),
        float(t == "process"),
        float(t == "file"),
        float(t == "lateral"),
        float(t == "discovery"),
        float(t == "unknown"),
    ]

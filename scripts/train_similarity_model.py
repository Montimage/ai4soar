#!/usr/bin/env python3
"""
Train the Path C similarity-based playbook recommender.

Supports two target modes (--target):
  technique  Predict MITRE T-code (e.g. T1021.002) — matches Path A/B precision.
             Uses datasets/eval/path_c_train.jsonl  (DEFAULT).
  tactic     Predict ATT&CK tactic phase — coarser, legacy mode.
             Uses datasets/otrf_normalized.jsonl by default.

Pipeline:
  1. Load dataset (eval nested-format or legacy flat format — auto-detected)
  2. Split by SCENARIO (not by event) — critical for generalization testing
  3. Fit TF-IDF + structured feature engineer on training split only
  4. Train five models and compare:
       Single-label: KNN (cosine), LR-balanced
       Multi-label:  OvR(LR-balanced), OvR(SVM-balanced, calibrated)
       Gradient boost: XGBoost (multi:softprob, scale_pos_weight)
  5. Evaluate: Precision@1/3/5 (primary label + any label), per-class F1
  6. Print summary comparison table
  7. Save all models + feature engineer to models/

Run from project root:
    python3 scripts/train_similarity_model.py                      # T-codes (recommended)
    python3 scripts/train_similarity_model.py --target tactic      # legacy tactic mode
    python3 scripts/train_similarity_model.py --dataset datasets/eval/path_c_train.jsonl
"""

import argparse
import json
import logging
import os
import sys
from collections import Counter
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.multiclass import OneVsRestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, MultiLabelBinarizer
from sklearn.svm import LinearSVC

from core.intelligent_orchestration.feature_engineer import AlertFeatureEngineer
from core.intelligent_orchestration.normalizer import NormalizedAlert

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

MODEL_DIR    = "models"
KNN_PATH     = os.path.join(MODEL_DIR, "knn_recommender.joblib")
LR_PATH      = os.path.join(MODEL_DIR, "lr_recommender.joblib")
OVR_LR_PATH  = os.path.join(MODEL_DIR, "ovr_lr_recommender.joblib")
OVR_SVM_PATH = os.path.join(MODEL_DIR, "ovr_svm_recommender.joblib")
RF_PATH      = os.path.join(MODEL_DIR, "rf_recommender.joblib")
MLP_PATH     = os.path.join(MODEL_DIR, "mlp_recommender.joblib")
XGB_PATH     = os.path.join(MODEL_DIR, "xgb_recommender.joblib")
FE_PATH      = os.path.join(MODEL_DIR, "feature_engineer.joblib")
MLB_PATH     = os.path.join(MODEL_DIR, "label_binarizer.joblib")
LE_PATH      = os.path.join(MODEL_DIR, "label_encoder.joblib")

DEFAULT_DATASET_TECHNIQUE = "datasets/eval/path_c_train.jsonl"
DEFAULT_DATASET_TACTIC    = "datasets/otrf_normalized.jsonl"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_records(path: str) -> list:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def records_to_alerts(records: list):
    """
    Parse legacy flat format (datasets/otrf_normalized.jsonl).

    Returns:
        alerts        — list of NormalizedAlert
        single_labels — list[str]        primary tactic per event
        multi_labels  — list[list[str]]  all tactics per event
        scenario_ids  — list[str]
    """
    alerts, single_labels, multi_labels, scenario_ids = [], [], [], []
    for r in records:
        primary  = r.get("tactic", "unknown")
        all_tacs = r.get("tactics", [])
        if not all_tacs:
            all_tacs = [primary] if primary != "unknown" else []
        all_tacs = [t for t in all_tacs if t != "unknown"]
        if not all_tacs:
            continue

        alerts.append(NormalizedAlert(
            raw_text=r.get("raw_text", ""),
            event_type=r.get("event_type", "unknown"),
            severity=float(r.get("severity", 0.0)),
            src_is_private=bool(r.get("src_is_private", False)),
            dst_is_private=bool(r.get("dst_is_private", False)),
            src_port_range=r.get("src_port_range", "unknown"),
            has_user=bool(r.get("has_user", False)),
            has_network=bool(r.get("has_network", False)),
            has_process=bool(r.get("has_process", False)),
            source_format=r.get("source_format", "unknown"),
        ))
        single_labels.append(primary if primary != "unknown" else all_tacs[0])
        multi_labels.append(all_tacs)
        scenario_ids.append(r.get("scenario_id", "unknown"))

    return alerts, single_labels, multi_labels, scenario_ids


def records_to_alerts_eval(records: list, target: str = "technique"):
    """
    Parse eval nested format (datasets/eval/path_c_train.jsonl).

    Each record has {"features": {...}, "ground_truth": {...}}.
    target="technique"  → labels are T-codes  (e.g. "T1021.002")
    target="tactic"     → labels are tactics  (e.g. "lateral-movement")

    Returns:
        alerts        — list of NormalizedAlert
        single_labels — list[str]        primary label per event
        multi_labels  — list[list[str]]  all labels per event
        scenario_ids  — list[str]
    """
    alerts, single_labels, multi_labels, scenario_ids = [], [], [], []
    for r in records:
        feat = r.get("features", {})
        gt   = r.get("ground_truth", {})

        if target == "technique":
            techniques = [t for t in gt.get("technique_ids", []) if t]
            if not techniques:
                continue
            primary    = techniques[0]
            all_labels = techniques
        else:
            primary    = gt.get("primary_tactic", "unknown")
            all_labels = [t for t in gt.get("all_tactics", []) if t]
            if not all_labels or primary == "unknown":
                continue

        alerts.append(NormalizedAlert(
            raw_text=feat.get("text", ""),
            event_type=feat.get("event_type", "unknown"),
            severity=float(feat.get("severity", 0.0)),
            src_is_private=bool(feat.get("src_is_private", True)),
            dst_is_private=True,          # not present in eval features
            src_port_range="unknown",     # not present in eval features
            has_user=bool(feat.get("has_user", False)),
            has_network=bool(feat.get("has_network", False)),
            has_process=bool(feat.get("has_process", False)),
            source_format=feat.get("source_format", "unknown"),
        ))
        single_labels.append(primary)
        multi_labels.append(all_labels)
        scenario_ids.append(gt.get("scenario_id", "unknown"))

    return alerts, single_labels, multi_labels, scenario_ids


# ---------------------------------------------------------------------------
# Scenario-level split
# ---------------------------------------------------------------------------

def split_by_scenario(alerts, single_labels, multi_labels, scenario_ids,
                       test_ratio: float = 0.2, seed: int = 42):
    rng = np.random.default_rng(seed)
    unique = sorted(set(scenario_ids))
    rng.shuffle(unique)
    n_test   = max(1, int(len(unique) * test_ratio))
    test_set = set(unique[:n_test])

    tr_a, tr_sl, tr_ml = [], [], []
    te_a, te_sl, te_ml = [], [], []
    for a, sl, ml, sid in zip(alerts, single_labels, multi_labels, scenario_ids):
        if sid in test_set:
            te_a.append(a); te_sl.append(sl); te_ml.append(ml)
        else:
            tr_a.append(a); tr_sl.append(sl); tr_ml.append(ml)
    return tr_a, tr_sl, tr_ml, te_a, te_sl, te_ml


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def pk_single(y_true, y_proba, classes, k):
    """P@k — single ground truth label must appear in top-k."""
    hit = sum(
        y_true[i] in set(classes[j] for j in np.argsort(y_proba[i])[-k:])
        for i in range(len(y_true))
    )
    return hit / len(y_true)


def pk_multi(y_true_lists, y_proba, classes, k):
    """P@k — at least one true label in top-k."""
    hit = sum(
        any(t in set(classes[j] for j in np.argsort(y_proba[i])[-k:])
            for t in y_true_lists[i])
        for i in range(len(y_true_lists))
    )
    return hit / len(y_true_lists)


def collect_metrics(y_proba, classes, te_sl, te_ml) -> Dict[str, float]:
    """Compute P@1/3/5 for both primary-label and any-label ground truth."""
    return {
        "p1_primary": pk_single(te_sl, y_proba, classes, 1),
        "p3_primary": pk_single(te_sl, y_proba, classes, 3),
        "p5_primary": pk_single(te_sl, y_proba, classes, 5),
        "p1_any":     pk_multi(te_ml, y_proba, classes, 1),
        "p3_any":     pk_multi(te_ml, y_proba, classes, 3),
        "p5_any":     pk_multi(te_ml, y_proba, classes, 5),
    }


def evaluate_single(name: str, model, X_test, te_sl, te_ml) -> Dict[str, float]:
    y_proba = model.predict_proba(X_test)
    classes = np.array(model.classes_)
    y_pred  = model.predict(X_test)
    m = collect_metrics(y_proba, classes, te_sl, te_ml)

    logger.info(f"\n{'─'*55}")
    logger.info(f"  {name}  (single-label)")
    logger.info(f"  P@1/3/5 (primary): {m['p1_primary']:.3f} / {m['p3_primary']:.3f} / {m['p5_primary']:.3f}")
    logger.info(f"  P@1/3/5 (any):     {m['p1_any']:.3f} / {m['p3_any']:.3f} / {m['p5_any']:.3f}")
    logger.info(classification_report(te_sl, y_pred, zero_division=0))
    return m


def evaluate_multi(name: str, model, mlb: MultiLabelBinarizer,
                   X_test, te_sl, te_ml) -> Dict[str, float]:
    y_proba = model.predict_proba(X_test)
    classes = np.array(mlb.classes_)
    Y_true  = mlb.transform(te_ml)
    Y_pred  = model.predict(X_test)
    m = collect_metrics(y_proba, classes, te_sl, te_ml)

    logger.info(f"\n{'─'*55}")
    logger.info(f"  {name}  (multi-label OvR)")
    logger.info(f"  P@1/3/5 (primary): {m['p1_primary']:.3f} / {m['p3_primary']:.3f} / {m['p5_primary']:.3f}")
    logger.info(f"  P@1/3/5 (any):     {m['p1_any']:.3f} / {m['p3_any']:.3f} / {m['p5_any']:.3f}")
    logger.info(classification_report(Y_true, Y_pred,
                                      target_names=mlb.classes_, zero_division=0))
    return m


def evaluate_xgb(name: str, model, le: LabelEncoder,
                 X_test, te_sl, te_ml) -> Dict[str, float]:
    y_proba = model.predict_proba(X_test)
    classes = np.array(le.classes_)
    y_pred  = le.inverse_transform(model.predict(X_test))
    m = collect_metrics(y_proba, classes, te_sl, te_ml)

    logger.info(f"\n{'─'*55}")
    logger.info(f"  {name}  (XGBoost multi:softprob)")
    logger.info(f"  P@1/3/5 (primary): {m['p1_primary']:.3f} / {m['p3_primary']:.3f} / {m['p5_primary']:.3f}")
    logger.info(f"  P@1/3/5 (any):     {m['p1_any']:.3f} / {m['p3_any']:.3f} / {m['p5_any']:.3f}")
    logger.info(classification_report(te_sl, y_pred, zero_division=0))
    return m


def print_summary(results: Dict[str, Dict[str, float]]) -> None:
    """Print aligned comparison table for all models."""
    header = f"\n{'='*80}\n  SUMMARY — all models\n{'='*80}"
    logger.info(header)
    col = "{:<22} {:>8} {:>8} {:>8}   {:>8} {:>8} {:>8}"
    logger.info(col.format("Model", "P@1-pri", "P@3-pri", "P@5-pri",
                            "P@1-any", "P@3-any", "P@5-any"))
    logger.info("─" * 80)
    for name, m in results.items():
        logger.info(col.format(
            name,
            f"{m['p1_primary']:.3f}", f"{m['p3_primary']:.3f}", f"{m['p5_primary']:.3f}",
            f"{m['p1_any']:.3f}",     f"{m['p3_any']:.3f}",     f"{m['p5_any']:.3f}",
        ))
    logger.info("─" * 80)
    logger.info("  pri = primary tactic label only")
    logger.info("  any = at least one of all true tactic labels (multi-label GT)")
    logger.info("=" * 80)


# ---------------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------------

def _is_eval_format(records: list) -> bool:
    """Auto-detect nested eval format vs legacy flat format."""
    return bool(records) and "features" in records[0] and "ground_truth" in records[0]


def train(dataset_path: str, target: str = "technique") -> None:
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found: {dataset_path}")
        sys.exit(1)

    logger.info(f"Loading dataset from {dataset_path}  (target={target})")
    records = load_records(dataset_path)
    logger.info(f"  {len(records)} records loaded")

    if _is_eval_format(records):
        logger.info("  Detected eval nested format (features + ground_truth)")
        alerts, single_labels, multi_labels, scenario_ids = records_to_alerts_eval(
            records, target=target
        )
    else:
        logger.info("  Detected legacy flat format")
        alerts, single_labels, multi_labels, scenario_ids = records_to_alerts(records)

    logger.info(f"  {len(alerts)} valid records after filtering")

    if len(alerts) < 20:
        logger.error("Dataset too small — need at least 20 events.")
        sys.exit(1)

    label_noun = "T-code" if target == "technique" else "tactic"
    logger.info(f"\nLabel distribution (primary {label_noun}):")
    bar_scale = max(1, max(Counter(single_labels).values()) // 40)
    for label, count in Counter(single_labels).most_common():
        bar = "█" * (count // bar_scale)
        logger.info(f"  {label:<30} {count:>5}  {bar}")
    multi_count = sum(1 for ml in multi_labels if len(ml) > 1)
    logger.info(f"\n  Events with >1 {label_noun} label: {multi_count} "
                f"({100*multi_count/len(alerts):.1f}%)")

    tr_a, tr_sl, tr_ml, te_a, te_sl, te_ml = split_by_scenario(
        alerts, single_labels, multi_labels, scenario_ids
    )
    logger.info(f"\nSplit: {len(tr_a)} train / {len(te_a)} test  (scenario-level)")

    if len(set(tr_sl)) < 2:
        logger.error("Training set has fewer than 2 tactic classes.")
        sys.exit(1)

    # Feature engineering — fit on TRAINING data only
    logger.info("\nFitting feature engineer on training data...")
    fe = AlertFeatureEngineer(n_tfidf=150)
    X_train = fe.fit_transform(tr_a)
    X_test  = fe.transform(te_a)
    logger.info(f"  Feature vector shape: {X_train.shape}")

    # Multi-label binarizer (for OvR models)
    mlb = MultiLabelBinarizer()
    Y_train = mlb.fit_transform(tr_ml)
    logger.info(f"  Multi-label classes ({len(mlb.classes_)}): {list(mlb.classes_)}")

    # Label encoder (for XGBoost — needs integer targets)
    le = LabelEncoder()
    y_train_enc = le.fit_transform(tr_sl)
    logger.info(f"  Single-label classes ({len(le.classes_)}): {list(le.classes_)}")

    results: Dict[str, Dict[str, float]] = {}

    # =========================================================
    # SINGLE-LABEL MODELS
    # =========================================================
    logger.info("\n" + "=" * 55)
    logger.info("SINGLE-LABEL MODELS")
    logger.info("=" * 55)

    logger.info("\nTraining KNN (k=5, cosine, distance-weighted)...")
    knn = KNeighborsClassifier(
        n_neighbors=min(5, len(tr_a) - 1),
        metric="cosine", algorithm="brute", weights="distance",
    )
    knn.fit(X_train, tr_sl)
    results["KNN"] = evaluate_single("KNN", knn, X_test, te_sl, te_ml)

    logger.info("\nTraining LR (multinomial, class_weight=balanced)...")
    lr = LogisticRegression(
        C=1.0, class_weight="balanced",
        max_iter=1000, solver="lbfgs", multi_class="multinomial", random_state=42,
    )
    lr.fit(X_train, tr_sl)
    results["LR-balanced"] = evaluate_single("LR-balanced", lr, X_test, te_sl, te_ml)

    # =========================================================
    # MULTI-LABEL MODELS
    # =========================================================
    logger.info("\n" + "=" * 55)
    logger.info("MULTI-LABEL MODELS  (OneVsRest)")
    logger.info("=" * 55)

    logger.info("\nTraining OvR(LR-balanced)...")
    ovr_lr = OneVsRestClassifier(
        LogisticRegression(
            C=1.0, class_weight="balanced",
            max_iter=1000, solver="lbfgs", random_state=42,
        ),
        n_jobs=-1,
    )
    ovr_lr.fit(X_train, Y_train)
    results["OvR-LR"] = evaluate_multi("OvR-LR-balanced", ovr_lr, mlb, X_test, te_sl, te_ml)

    logger.info("\nTraining OvR(LinearSVC-balanced, calibrated)...")
    ovr_svm = OneVsRestClassifier(
        CalibratedClassifierCV(
            LinearSVC(C=1.0, class_weight="balanced", max_iter=5000, dual=False),
            cv=3,
        ),
        n_jobs=-1,
    )
    ovr_svm.fit(X_train, Y_train)
    results["OvR-SVM"] = evaluate_multi("OvR-SVM-balanced", ovr_svm, mlb, X_test, te_sl, te_ml)

    # =========================================================
    # RANDOM FOREST
    # =========================================================
    logger.info("\n" + "=" * 55)
    logger.info("ENSEMBLE MODELS")
    logger.info("=" * 55)

    logger.info("\nTraining RandomForest (n=300, class_weight=balanced_subsample)...")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, tr_sl)
    results["RF"] = evaluate_single("RandomForest", rf, X_test, te_sl, te_ml)

    # =========================================================
    # MLP
    # =========================================================
    logger.info("\n" + "=" * 55)
    logger.info("NEURAL NETWORK")
    logger.info("=" * 55)

    logger.info("\nTraining MLP (256-128 hidden, ReLU, Adam, early stopping)...")
    mlp = MLPClassifier(
        hidden_layer_sizes=(256, 128),
        activation="relu",
        solver="adam",
        learning_rate_init=1e-3,
        max_iter=200,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=15,
        random_state=42,
    )
    mlp.fit(X_train, tr_sl)
    results["MLP"] = evaluate_single("MLP", mlp, X_test, te_sl, te_ml)

    # =========================================================
    # XGBOOST
    # =========================================================
    logger.info("\n" + "=" * 55)
    logger.info("GRADIENT BOOSTING  (XGBoost)")
    logger.info("=" * 55)

    try:
        from xgboost import XGBClassifier

        n_classes = len(le.classes_)
        # Scale pos weight not directly applicable to multi-class; use sample_weight instead
        class_counts = Counter(tr_sl)
        total        = len(tr_sl)
        sample_weight = np.array([
            total / (n_classes * class_counts[le.classes_[y]])
            for y in y_train_enc
        ])

        logger.info(f"\nTraining XGBoost (n_estimators=300, max_depth=6, "
                    f"subsample=0.8, colsample_bytree=0.8)...")
        xgb = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="multi:softprob",
            num_class=n_classes,
            eval_metric="mlogloss",
            use_label_encoder=False,
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
        xgb.fit(X_train, y_train_enc, sample_weight=sample_weight)
        results["XGBoost"] = evaluate_xgb("XGBoost", xgb, le, X_test, te_sl, te_ml)

    except ImportError:
        logger.warning("xgboost not installed — skipping. Run: pip3 install xgboost")
        xgb = None

    # =========================================================
    # Summary table
    # =========================================================
    print_summary(results)

    # =========================================================
    # Save
    # =========================================================
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(knn,     KNN_PATH)
    joblib.dump(lr,      LR_PATH)
    joblib.dump(ovr_lr,  OVR_LR_PATH)
    joblib.dump(ovr_svm, OVR_SVM_PATH)
    joblib.dump(rf,      RF_PATH)
    joblib.dump(mlp,     MLP_PATH)
    if xgb is not None:
        joblib.dump(xgb, XGB_PATH)
    joblib.dump(mlb, MLB_PATH)
    joblib.dump(le,  LE_PATH)
    fe.save(FE_PATH)

    logger.info("\nModels saved to models/")
    logger.info("Set SIMILARITY_MODEL=  knn | lr | ovr_lr | ovr_svm | xgb")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Path C similarity model")
    parser.add_argument(
        "--target",
        choices=["technique", "tactic"],
        default="technique",
        help="Classification target: T-code (recommended) or tactic phase (legacy). Default: technique",
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to training JSONL. Default: datasets/eval/path_c_train.jsonl (technique) "
             "or datasets/otrf_normalized.jsonl (tactic)",
    )
    args   = parser.parse_args()
    ds     = args.dataset or (
        DEFAULT_DATASET_TECHNIQUE if args.target == "technique" else DEFAULT_DATASET_TACTIC
    )
    train(ds, target=args.target)

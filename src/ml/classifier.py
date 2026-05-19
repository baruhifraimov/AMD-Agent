"""LightGBM classifier with FPR-aware threshold tuning."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
from sklearn.metrics import roc_curve

from src.config import (
    BENIGN_DIR,
    FEATURE_NAMES,
    MIN_TRAIN_BENIGN,
    MIN_TRAIN_MALWARE,
    MODEL_PATH,
    TARGET_FPR,
    allow_local_benign,
    ensure_dirs,
)
import src.db.tracker as db
from src.ml.features import extract_pe_features, features_to_vector, vectorize_batch

logger = logging.getLogger(__name__)


def load_bundle(path: Path | None = None) -> dict[str, Any] | None:
    ensure_dirs()
    p = path or MODEL_PATH
    if not p.exists():
        return None
    return joblib.load(p)


def save_bundle(
    model: lgb.LGBMClassifier,
    threshold: float,
    *,
    path: Path | None = None,
    training_counts: dict[int, int] | None = None,
) -> None:
    ensure_dirs()
    p = path or MODEL_PATH
    bundle: dict[str, Any] = {
        "model": model,
        "threshold": threshold,
        "feature_names": FEATURE_NAMES,
    }
    if training_counts is not None:
        bundle["training_counts"] = {
            str(label): int(count) for label, count in training_counts.items()
        }
    joblib.dump(
        bundle,
        p,
    )


def fit_threshold(
    y_true: np.ndarray,
    y_score: np.ndarray,
    target_fpr: float = TARGET_FPR,
) -> float:
    """Pick decision threshold achieving FPR <= target on validation set."""
    if len(np.unique(y_true)) < 2:
        return 0.5
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    # thresholds[i] corresponds to fpr[i]; find largest threshold with fpr <= target
    valid = np.where(fpr <= target_fpr)[0]
    if len(valid) == 0:
        return float(thresholds[0]) if len(thresholds) else 0.5
    idx = valid[-1]
    return float(thresholds[idx])


def predict_proba(model: lgb.LGBMClassifier, X: np.ndarray) -> np.ndarray:
    return model.predict_proba(X)[:, 1]


def ingest_benign_corpus(tracker: db.MalwareTracker) -> int:
    """Extract features from data/benign/*.bin and register as label=0."""
    count = 0
    if not BENIGN_DIR.exists():
        return 0
    for path in BENIGN_DIR.glob("*"):
        if not path.is_file():
            continue
        sha = path.stem.lower()
        if tracker.hash_exists(sha):
            continue
        if not path.read_bytes()[:2] == b"MZ":
            continue
        feats = extract_pe_features(path)
        if feats is None:
            continue
        tracker.insert_sample(
            sha,
            str(path),
            tracker.utc_now_iso(),
            features=feats,
            label=0,
        )
        count += 1
    return count


def build_training_arrays(
    tracker: db.MalwareTracker,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    rows = tracker.fetch_labeled_with_features()
    hashes: list[str] = []
    X_list: list[np.ndarray] = []
    y_list: list[int] = []
    for row in rows:
        feats = row.get("features")
        if not feats:
            continue
        hashes.append(row["sha256"])
        X_list.append(features_to_vector(feats))
        y_list.append(int(row["label"]))
    if not X_list:
        return np.empty((0, len(FEATURE_NAMES))), np.array([]), []
    return np.vstack(X_list), np.array(y_list, dtype=int), hashes


def class_counts_from_labels(y: np.ndarray) -> dict[int, int]:
    """Count labels in the actual feature-bearing training set."""
    return {int(label): int(np.sum(y == label)) for label in np.unique(y)}


def training_targets_met(counts: dict[int, int]) -> bool:
    return counts.get(1, 0) >= MIN_TRAIN_MALWARE and counts.get(0, 0) >= MIN_TRAIN_BENIGN


def model_bundle_ready(bundle: dict[str, Any] | None) -> bool:
    if bundle is None:
        return False
    raw_counts = bundle.get("training_counts")
    if not isinstance(raw_counts, dict):
        return False
    counts = {int(label): int(count) for label, count in raw_counts.items()}
    return training_targets_met(counts)


def cold_start_train(tracker: db.MalwareTracker) -> dict[str, Any] | None:
    """Train initial LightGBM when enough labeled samples exist."""
    if allow_local_benign():
        ingest_benign_corpus(tracker)
    X, y, _ = build_training_arrays(tracker)
    counts = class_counts_from_labels(y)
    n_mal = counts.get(1, 0)
    n_ben = counts.get(0, 0)
    if not training_targets_met(counts):
        logger.info(
            "Cold-start skipped: malware=%d/%d benign=%d/%d",
            n_mal,
            MIN_TRAIN_MALWARE,
            n_ben,
            MIN_TRAIN_BENIGN,
        )
        return None

    n = len(y)
    train_end = int(n * 0.7)
    val_end = int(n * 0.85)
    X_train, y_train = X[:train_end], y[:train_end]
    X_val, y_val = X[train_end:val_end], y[train_end:val_end]
    if len(np.unique(y_train)) < 2:
        logger.warning(
            "Cold-start skipped: chronological train split has fewer than 2 classes "
            "(n_train=%d, classes=%s)",
            len(y_train),
            np.unique(y_train).tolist(),
        )
        return None

    model = lgb.LGBMClassifier(
        n_estimators=100,
        learning_rate=0.05,
        max_depth=6,
        random_state=42,
        verbose=-1,
    )
    model.fit(X_train, y_train)
    val_scores = predict_proba(model, X_val) if len(y_val) else np.array([0.5])
    threshold = fit_threshold(y_val, val_scores) if len(y_val) else 0.5
    save_bundle(model, threshold, training_counts=counts)
    logger.info("Cold-start model trained on %d samples", n)
    return load_bundle()


def retrain_model(
    X: np.ndarray,
    y: np.ndarray,
    *,
    val_fraction: float = 0.15,
) -> dict[str, Any] | None:
    """Retrain LightGBM and tune threshold on validation tail."""
    n = len(y)
    val_start = max(1, int(n * (1 - val_fraction)))
    X_train, y_train = X[:val_start], y[:val_start]
    X_val, y_val = X[val_start:], y[val_start:]

    if len(np.unique(y_train)) < 2:
        logger.warning(
            "Retrain skipped: y_train contains fewer than 2 classes "
            "(n_train=%d, classes=%s); reusing existing model bundle",
            len(y_train),
            np.unique(y_train).tolist(),
        )
        return load_bundle()

    model = lgb.LGBMClassifier(
        n_estimators=150,
        learning_rate=0.05,
        max_depth=6,
        random_state=42,
        verbose=-1,
    )
    model.fit(X_train, y_train)
    val_scores = predict_proba(model, X_val) if len(y_val) else predict_proba(model, X_train)
    y_for_thr = y_val if len(y_val) else y_train
    threshold = fit_threshold(y_for_thr, val_scores[: len(y_for_thr)])
    save_bundle(model, threshold, training_counts=class_counts_from_labels(y))
    return load_bundle()


def score_samples(
    bundle: dict[str, Any],
    feature_dicts: list[dict[str, Any]],
    hashes: list[str],
) -> dict[str, float]:
    """Return hash -> malicious probability."""
    if not feature_dicts:
        return {}
    X = vectorize_batch(feature_dicts)
    model: lgb.LGBMClassifier = bundle["model"]
    probs = predict_proba(model, X)
    return {h: float(p) for h, p in zip(hashes, probs)}

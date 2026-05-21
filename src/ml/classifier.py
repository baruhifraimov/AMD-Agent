"""LightGBM classifier with feature selection and FPR-aware tuning."""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

from src.config import (
    BENIGN_DIR,
    FEATURE_DIM,
    FEATURE_NAMES,
    FEATURE_SELECTION_K,
    FEATURE_SET_VERSION,
    MIN_TRAIN_BENIGN,
    MIN_TRAIN_MALWARE,
    MODEL_PATH,
    OPTUNA_TIMEOUT,
    OPTUNA_TRIALS,
    TARGET_FPR,
    allow_local_benign,
    ensure_dirs,
)
import src.db.tracker as db
from src.ml.features import extract_pe_features, features_to_vector, vectorize_batch
from src.ml.splits import stratified_split, temporal_split

logger = logging.getLogger(__name__)

try:  # Optional fallback keeps source-mounted Docker runs alive before rebuild.
    import optuna
except Exception:  # pragma: no cover - old image/local env fallback.
    optuna = None

try:  # Optional fallback keeps source-mounted Docker runs alive before rebuild.
    import xgboost as xgb
except Exception:  # pragma: no cover - old image/local env fallback.
    xgb = None


def _bundle_feature_compatible(bundle: dict[str, Any]) -> bool:
    if bundle.get("feature_set_version") != FEATURE_SET_VERSION:
        return False
    if int(bundle.get("feature_dim", 0) or 0) != FEATURE_DIM:
        return False
    names = bundle.get("feature_names")
    return isinstance(names, list) and len(names) == len(FEATURE_NAMES)


def load_bundle(path: Path | None = None) -> dict[str, Any] | None:
    ensure_dirs()
    p = path or MODEL_PATH
    if not p.exists():
        return None
    bundle = joblib.load(p)
    if not _bundle_feature_compatible(bundle):
        logger.warning(
            "Model feature set is stale; expected %s/%d, got %s/%s",
            FEATURE_SET_VERSION,
            FEATURE_DIM,
            bundle.get("feature_set_version"),
            bundle.get("feature_dim"),
        )
    return bundle


def _save_bundle_dict(bundle: dict[str, Any], path: Path | None = None) -> None:
    ensure_dirs()
    joblib.dump(bundle, path or MODEL_PATH)


def save_bundle(
    model: lgb.LGBMClassifier,
    threshold: float,
    *,
    path: Path | None = None,
    training_counts: dict[int, int] | None = None,
    selected_feature_indices: list[int] | None = None,
    optuna_best_params: dict[str, Any] | None = None,
    bootstrap_sanity_metrics: dict[str, float] | None = None,
    split_metadata: dict[str, Any] | None = None,
) -> None:
    selected = selected_feature_indices or list(range(len(FEATURE_NAMES)))
    bundle: dict[str, Any] = {
        "model": model,
        "threshold": float(threshold),
        "feature_names": FEATURE_NAMES,
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_dim": FEATURE_DIM,
        "selected_feature_indices": selected,
        "selected_feature_names": [FEATURE_NAMES[i] for i in selected],
        "optuna_best_params": optuna_best_params or {},
    }
    if training_counts is not None:
        bundle["training_counts"] = {
            str(label): int(count) for label, count in training_counts.items()
        }
    if split_metadata is not None:
        bundle["split_metadata"] = split_metadata
    if bootstrap_sanity_metrics is not None:
        bundle["bootstrap_sanity_metrics"] = bootstrap_sanity_metrics
    _save_bundle_dict(bundle, path)


def fit_threshold(
    y_true: np.ndarray,
    y_score: np.ndarray,
    target_fpr: float = TARGET_FPR,
) -> float:
    """Pick a finite threshold with maximal TPR while FPR stays below target."""
    if len(y_true) == 0 or len(y_score) == 0 or len(np.unique(y_true)) < 2:
        return 0.5
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    valid = np.where(fpr <= target_fpr)[0]
    if len(valid) == 0:
        return 1.0
    valid_tpr = tpr[valid]
    best_tpr = float(np.max(valid_tpr))
    candidates = valid[np.where(valid_tpr == best_tpr)[0]]
    idx = int(candidates[-1])
    threshold = float(thresholds[idx])
    if not math.isfinite(threshold):
        return 1.0
    return min(max(threshold, 0.0), 1.0)


def _feature_frame(X: np.ndarray, feature_names: list[str] | None = None) -> pd.DataFrame:
    """Align inference/training matrices with LightGBM feature name expectations."""
    columns = list(feature_names or FEATURE_NAMES)
    if X.ndim == 1:
        X = X.reshape(1, -1)
    return pd.DataFrame(X, columns=columns)


def predict_proba(
    model: lgb.LGBMClassifier,
    X: np.ndarray,
    *,
    feature_names: list[str] | None = None,
) -> np.ndarray:
    if X.size == 0:
        return np.array([], dtype=np.float64)
    return np.asarray(
        model.predict_proba(_feature_frame(X, feature_names))[:, 1],
        dtype=np.float64,
    )


def _binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    if len(y_true) == 0:
        return {}
    y_pred = (scores >= threshold).astype(int)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    acc = (tp + tn) / max(len(y_true), 1)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "tpr": float(recall),
        "fpr": float(fpr),
        "threshold": float(threshold),
        "support": float(len(y_true)),
    }


def _adaptive_min_data_in_leaf(n_train: int) -> int:
    return max(5, n_train // 20)


def _lgbm_default_params(n_train: int | None = None) -> dict[str, Any]:
    n = max(1, int(n_train or 100))
    return {
        "n_estimators": 150,
        "learning_rate": 0.05,
        "max_depth": -1,
        "num_leaves": 31,
        "min_data_in_leaf": _adaptive_min_data_in_leaf(n),
        "class_weight": "balanced",
        "random_state": 42,
        "verbose": -1,
    }


def _min_leaf_optuna_bounds(n_train: int) -> tuple[int, int]:
    floor = 5 if n_train < 500 else 20
    adaptive = _adaptive_min_data_in_leaf(n_train)
    return floor, max(adaptive, floor + 10, 80)


def _fit_lightgbm(
    model: lgb.LGBMClassifier,
    X_train: np.ndarray,
    y_train: np.ndarray,
    *,
    feature_names: list[str],
    X_val: np.ndarray | None = None,
    y_val: np.ndarray | None = None,
) -> lgb.LGBMClassifier:
    train_frame = _feature_frame(X_train, feature_names)
    if (
        X_val is not None
        and y_val is not None
        and len(y_val) > 0
        and len(np.unique(y_val)) == 2
    ):
        val_frame = _feature_frame(X_val, feature_names)
        model.fit(
            train_frame,
            y_train,
            eval_set=[(val_frame, y_val)],
            callbacks=[lgb.early_stopping(20, verbose=False)],
        )
        return model
    model.fit(train_frame, y_train)
    return model


def _apply_selected(X: np.ndarray, selected: list[int] | np.ndarray) -> np.ndarray:
    if X.size == 0:
        return X.reshape(0, len(selected))
    return X[:, np.asarray(selected, dtype=int)]


def _rank_features_xgboost(X_train: np.ndarray, y_train: np.ndarray, k: int) -> list[int]:
    k = max(1, min(k, X_train.shape[1]))
    if xgb is not None and len(np.unique(y_train)) == 2:
        try:
            ranker = xgb.XGBClassifier(
                n_estimators=80,
                max_depth=4,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                objective="binary:logistic",
                eval_metric="logloss",
                tree_method="hist",
                n_jobs=1,
                random_state=42,
            )
            ranker.fit(X_train, y_train)
            importances = np.asarray(ranker.feature_importances_, dtype=np.float64)
            if importances.shape[0] == X_train.shape[1] and np.any(importances > 0):
                return np.argsort(importances)[::-1][:k].astype(int).tolist()
        except Exception as exc:
            logger.warning("XGBoost feature ranking failed; falling back to variance: %s", exc)

    variances = np.var(X_train, axis=0)
    if not np.any(variances > 0):
        return list(range(k))
    return np.argsort(variances)[::-1][:k].astype(int).tolist()


def _trial_score(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    *,
    target_fpr: float = TARGET_FPR,
) -> float:
    metrics = _binary_metrics(y_true, scores, threshold)
    fpr = metrics.get("fpr", 1.0)
    tpr = metrics.get("tpr", 0.0)
    if fpr > target_fpr:
        return float(tpr - (fpr - target_fpr) * 100.0)
    return float(tpr)


def _optimize_lightgbm_params(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    *,
    optimize: bool,
    feature_names: list[str],
) -> dict[str, Any]:
    base = _lgbm_default_params(len(y_train))
    if (
        not optimize
        or optuna is None
        or OPTUNA_TRIALS <= 0
        or len(y_val) == 0
        or len(np.unique(y_val)) < 2
    ):
        return base

    leaf_low, leaf_high = _min_leaf_optuna_bounds(len(y_train))
    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial: Any) -> float:
        params = {
            **base,
            "num_leaves": trial.suggest_int("num_leaves", 31, 64),
            "n_estimators": trial.suggest_int("n_estimators", 100, 500),
            "min_data_in_leaf": trial.suggest_int("min_data_in_leaf", leaf_low, leaf_high),
        }
        model = lgb.LGBMClassifier(**params)
        _fit_lightgbm(
            model,
            X_train,
            y_train,
            feature_names=feature_names,
            X_val=X_val,
            y_val=y_val,
        )
        scores = predict_proba(model, X_val, feature_names=feature_names)
        threshold = fit_threshold(y_val, scores)
        return _trial_score(y_val, scores, threshold)

    try:
        study = optuna.create_study(direction="maximize")
        timeout = OPTUNA_TIMEOUT if OPTUNA_TIMEOUT > 0 else None
        study.optimize(objective, n_trials=OPTUNA_TRIALS, timeout=timeout, show_progress_bar=False)
        if study.best_params:
            return {**base, **study.best_params}
    except Exception as exc:
        logger.warning("Optuna tuning failed; using default LightGBM params: %s", exc)
    return base


def _split_metadata(
    *,
    split_mode: str,
    y_train: np.ndarray,
    y_val: np.ndarray,
    y_test: np.ndarray | None = None,
    threshold_target_fpr: float = TARGET_FPR,
) -> dict[str, Any]:
    val_benign = int(np.sum(y_val == 0)) if len(y_val) else 0
    min_observable_fpr = 1.0 / val_benign if val_benign else 1.0
    meta: dict[str, Any] = {
        "split_mode": split_mode,
        "train_class_counts": class_counts_from_labels(y_train),
        "val_class_counts": class_counts_from_labels(y_val) if len(y_val) else {},
        "threshold_target_fpr": float(threshold_target_fpr),
        "threshold_validation_benign": val_benign,
        "threshold_min_observable_fpr": float(min_observable_fpr),
        "threshold_target_supported": bool(
            val_benign > 0 and min_observable_fpr <= threshold_target_fpr
        ),
    }
    if y_test is not None and len(y_test):
        meta["test_class_counts"] = class_counts_from_labels(y_test)
    return meta


def _resolve_selected_features(
    X_train: np.ndarray,
    y_train: np.ndarray,
    frozen_feature_indices: list[int] | None,
) -> list[int]:
    if frozen_feature_indices is not None:
        valid = [i for i in frozen_feature_indices if 0 <= i < X_train.shape[1]]
        if valid:
            return valid
    return _rank_features_xgboost(X_train, y_train, FEATURE_SELECTION_K)


def fit_model_artifact(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    *,
    training_counts: dict[int, int] | None = None,
    optimize: bool = True,
    bootstrap_sanity_metrics: dict[str, float] | None = None,
    frozen_feature_indices: list[int] | None = None,
    split_mode: str = "temporal",
) -> dict[str, Any]:
    if len(np.unique(y_train)) < 2:
        raise ValueError("training split has fewer than 2 classes")
    selected = _resolve_selected_features(X_train, y_train, frozen_feature_indices)
    selected_names = [FEATURE_NAMES[i] for i in selected]
    X_train_sel = _apply_selected(X_train, selected)
    X_val_sel = _apply_selected(X_val, selected) if len(y_val) else np.empty((0, len(selected)))
    params = _optimize_lightgbm_params(
        X_train_sel,
        y_train,
        X_val_sel,
        y_val,
        optimize=optimize,
        feature_names=selected_names,
    )
    model = lgb.LGBMClassifier(**params)
    _fit_lightgbm(
        model,
        X_train_sel,
        y_train,
        feature_names=selected_names,
        X_val=X_val_sel if len(y_val) else None,
        y_val=y_val if len(y_val) else None,
    )
    val_scores = predict_proba(model, X_val_sel, feature_names=selected_names) if len(y_val) else np.array([])
    threshold = fit_threshold(y_val, val_scores) if len(y_val) else 0.5
    threshold_meta = _split_metadata(
        split_mode=split_mode,
        y_train=y_train,
        y_val=y_val,
    )
    if not threshold_meta["threshold_target_supported"] and len(y_val):
        logger.info(
            "Threshold target FPR %.4f is below validation resolution %.4f "
            "(benign=%d); treating threshold as small-sample calibration",
            TARGET_FPR,
            threshold_meta["threshold_min_observable_fpr"],
            threshold_meta["threshold_validation_benign"],
        )
    bundle: dict[str, Any] = {
        "model": model,
        "threshold": threshold,
        "feature_names": FEATURE_NAMES,
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_dim": FEATURE_DIM,
        "selected_feature_indices": selected,
        "selected_feature_names": selected_names,
        "optuna_best_params": params,
        "split_metadata": threshold_meta,
    }
    if training_counts is not None:
        bundle["training_counts"] = {
            str(label): int(count) for label, count in training_counts.items()
        }
    if bootstrap_sanity_metrics is not None:
        bundle["bootstrap_sanity_metrics"] = bootstrap_sanity_metrics
    return bundle


def _score_matrix(bundle: dict[str, Any], X: np.ndarray) -> np.ndarray:
    selected = list(bundle.get("selected_feature_indices") or range(X.shape[1]))
    selected_names = list(bundle.get("selected_feature_names") or [FEATURE_NAMES[i] for i in selected])
    X_selected = _apply_selected(X, selected)
    return predict_proba(bundle["model"], X_selected, feature_names=selected_names)


def score_feature_matrix(bundle: dict[str, Any], X: np.ndarray) -> np.ndarray:
    """Score a full feature matrix with a saved or temporary model artifact."""
    return _score_matrix(bundle, X)


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


def _row_feature_current(row: dict[str, Any]) -> bool:
    return (
        row.get("feature_version") == FEATURE_SET_VERSION
        and int(row.get("feature_dim") or 0) == FEATURE_DIM
    )


def _refresh_stale_features(tracker: db.MalwareTracker, row: dict[str, Any]) -> dict[str, Any] | None:
    if _row_feature_current(row):
        return row.get("features")
    file_path = row.get("file_path")
    if not file_path or not Path(file_path).exists():
        logger.info("Skipping stale feature row without readable file: %s", row.get("sha256", "")[:12])
        return None
    features = extract_pe_features(file_path)
    if features is None:
        logger.info("Skipping stale feature row that failed re-extraction: %s", row.get("sha256", "")[:12])
        return None
    tracker.update_features(str(row["sha256"]), features)
    return features


def build_training_arrays(
    tracker: db.MalwareTracker,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    rows = tracker.fetch_labeled_with_features()
    hashes: list[str] = []
    X_list: list[np.ndarray] = []
    y_list: list[int] = []
    refreshed = 0
    for row in rows:
        feats = _refresh_stale_features(tracker, row)
        if not feats:
            continue
        if not _row_feature_current(row):
            refreshed += 1
        hashes.append(row["sha256"])
        X_list.append(features_to_vector(feats))
        y_list.append(int(row["label"]))
    if refreshed:
        logger.info("Re-extracted %d stale feature row(s) for %s", refreshed, FEATURE_SET_VERSION)
    if not X_list:
        return np.empty((0, len(FEATURE_NAMES))), np.array([]), []
    return np.vstack(X_list), np.array(y_list, dtype=int), hashes


def class_counts_from_labels(y: np.ndarray) -> dict[int, int]:
    """Count labels in the actual feature-bearing training set."""
    return {int(label): int(np.sum(y == label)) for label in np.unique(y)}


def training_targets_met(counts: dict[int, int]) -> bool:
    return counts.get(1, 0) >= MIN_TRAIN_MALWARE and counts.get(0, 0) >= MIN_TRAIN_BENIGN


def model_bundle_ready(bundle: dict[str, Any] | None) -> bool:
    if bundle is None or not _bundle_feature_compatible(bundle):
        return False
    raw_counts = bundle.get("training_counts")
    if not isinstance(raw_counts, dict):
        return False
    counts = {int(label): int(count) for label, count in raw_counts.items()}
    return training_targets_met(counts)


def cold_start_train(tracker: db.MalwareTracker) -> dict[str, Any] | None:
    """Train initial LightGBM when enough current feature rows exist."""
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

    X_train, y_train, X_val, y_val, X_test, y_test = stratified_split(
        X,
        y,
        val_fraction=0.15,
        test_fraction=0.15,
    )
    if len(np.unique(y_train)) < 2:
        logger.warning(
            "Cold-start skipped: stratified train split has fewer than 2 classes "
            "(n_train=%d, classes=%s)",
            len(y_train),
            np.unique(y_train).tolist(),
        )
        return None

    try:
        bundle = fit_model_artifact(
            X_train,
            y_train,
            X_val,
            y_val,
            training_counts=counts,
            optimize=True,
            split_mode="stratified",
        )
    except ValueError as exc:
        logger.warning("Cold-start skipped: %s", exc)
        return None

    _, _, _, _, X_sanity, y_sanity = stratified_split(
        X,
        y,
        val_fraction=0.0,
        test_fraction=0.15,
    )
    if len(y_sanity) and len(np.unique(y_sanity)) == 2:
        sanity_scores = _score_matrix(bundle, X_sanity)
        sanity = _binary_metrics(y_sanity, sanity_scores, float(bundle.get("threshold", 0.5)))
        bundle["bootstrap_sanity_metrics"] = sanity
        meta = dict(bundle.get("split_metadata") or {})
        meta["sanity_split_mode"] = "stratified"
        meta["sanity_class_counts"] = class_counts_from_labels(y_sanity)
        bundle["split_metadata"] = meta
        logger.info("Bootstrap stratified sanity eval: %s", sanity)

    _save_bundle_dict(bundle)
    logger.info(
        "Cold-start model trained on %d samples (train=%d val=%d test=%d selected_features=%d)",
        len(y),
        len(y_train),
        len(y_val),
        len(y_test),
        len(bundle.get("selected_feature_indices", [])),
    )
    return load_bundle()


def retrain_model(
    X: np.ndarray,
    y: np.ndarray,
    *,
    val_fraction: float = 0.15,
    frozen_feature_indices: list[int] | None = None,
) -> dict[str, Any] | None:
    """Retrain LightGBM with a chronological validation split."""
    if len(np.unique(y)) < 2:
        logger.warning(
            "Retrain skipped: y contains fewer than 2 classes (n=%d, classes=%s); "
            "reusing existing model bundle",
            len(y),
            np.unique(y).tolist(),
        )
        return load_bundle()

    train_ratio = max(0.5, 1.0 - val_fraction)
    X_train, y_train, X_val, y_val, _, _ = temporal_split(
        X,
        y,
        train_ratio=train_ratio,
        val_ratio=val_fraction,
    )
    if len(np.unique(y_train)) < 2:
        logger.warning(
            "Retrain skipped: y_train contains fewer than 2 classes "
            "(n_train=%d, classes=%s); reusing existing model bundle",
            len(y_train),
            np.unique(y_train).tolist(),
        )
        return load_bundle()

    frozen = frozen_feature_indices
    if frozen is None:
        existing = load_bundle()
        if existing and _bundle_feature_compatible(existing):
            raw = existing.get("selected_feature_indices")
            if isinstance(raw, list) and raw:
                frozen = [int(i) for i in raw]

    try:
        bundle = fit_model_artifact(
            X_train,
            y_train,
            X_val,
            y_val,
            training_counts=class_counts_from_labels(y),
            optimize=True,
            frozen_feature_indices=frozen,
            split_mode="temporal",
        )
    except ValueError as exc:
        logger.warning("Retrain skipped: %s", exc)
        return load_bundle()
    _save_bundle_dict(bundle)
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
    probs = _score_matrix(bundle, X)
    return {h: float(p) for h, p in zip(hashes, probs)}

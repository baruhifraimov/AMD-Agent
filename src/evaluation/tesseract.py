"""TESSERACT temporal evaluation — chronological train/val/test splits."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

import src.config as cfg
import src.db.tracker as db
from src.ml.classifier import (
    build_training_arrays,
    class_counts_from_labels,
    fit_model_artifact,
    load_bundle,
    model_bundle_ready,
    score_feature_matrix,
)

logger = logging.getLogger(__name__)


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, float]:
    """Accuracy, precision, recall, FPR."""
    acc = float(accuracy_score(y_true, y_pred))
    prec, rec, _, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return {
        "accuracy": acc,
        "precision": float(prec),
        "recall": float(rec),
        "tpr": float(tpr),
        "fpr": float(fpr),
    }


def run_tesseract_eval(
    tracker: db.MalwareTracker | None = None,
    *,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> dict[str, float]:
    """Chronological split evaluation on labeled DB samples."""
    tracker = tracker or db.get_tracker()
    X, y, _ = build_training_arrays(tracker)
    if len(y) < 5:
        logger.warning("Insufficient samples for TESSERACT eval: %d", len(y))
        return {}

    n = len(y)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))
    X_train, y_train = X[:train_end], y[:train_end]
    X_val, y_val = X[train_end:val_end], y[train_end:val_end]
    X_test, y_test = X[val_end:], y[val_end:]

    production_bundle = load_bundle()
    if not model_bundle_ready(production_bundle):
        return {}
    if len(np.unique(y_train)) < 2:
        logger.info("TESSERACT skipped: train split has a single class")
        return {}
    if len(np.unique(y_val)) < 2 or len(np.unique(y_test)) < 2:
        logger.info("TESSERACT skipped: single-class temporal validation/test split")
        return {}

    try:
        temporal_bundle = fit_model_artifact(
            X_train,
            y_train,
            X_val,
            y_val,
            training_counts=class_counts_from_labels(y_train),
            optimize=False,
        )
    except ValueError as exc:
        logger.info("TESSERACT skipped: %s", exc)
        return {}

    threshold = float(temporal_bundle.get("threshold", 0.5))
    test_scores = score_feature_matrix(temporal_bundle, X_test)
    y_pred = (test_scores >= threshold).astype(int)
    metrics = compute_metrics(y_test, y_pred)
    metrics["threshold"] = threshold
    metrics["target_fpr"] = cfg.TARGET_FPR
    metrics["split_mode_temporal"] = 1.0
    metrics["train_support"] = float(len(y_train))
    metrics["val_support"] = float(len(y_val))
    metrics["test_support"] = float(len(y_test))
    metrics["support"] = float(len(y_test))
    metrics["train_benign"] = float(np.sum(y_train == 0))
    metrics["train_malware"] = float(np.sum(y_train == 1))
    metrics["val_benign"] = float(np.sum(y_val == 0))
    metrics["val_malware"] = float(np.sum(y_val == 1))
    metrics["test_benign"] = float(np.sum(y_test == 0))
    metrics["test_malware"] = float(np.sum(y_test == 1))
    val_benign = int(np.sum(y_val == 0))
    min_observable_fpr = 1.0 / val_benign if val_benign else 1.0
    metrics["threshold_min_observable_fpr"] = float(min_observable_fpr)
    metrics["threshold_target_supported"] = (
        1.0 if val_benign > 0 and min_observable_fpr <= cfg.TARGET_FPR else 0.0
    )
    metrics["aut"] = compute_aut(_historical_metric_values("accuracy") + [metrics["accuracy"]])
    return metrics


def append_eval_log(metrics: dict[str, float], path: Path | None = None) -> None:
    cfg.ensure_dirs()
    p = path or cfg.EVAL_LOG_PATH
    record = {"metrics": metrics}
    with p.open("a") as f:
        f.write(json.dumps(record) + "\n")


def latest_eval_metrics(path: Path | None = None) -> dict[str, float]:
    """Return the last persisted TESSERACT metrics record, if any."""
    p = path or cfg.EVAL_LOG_PATH
    if not p.exists():
        return {}
    latest: dict[str, float] = {}
    with p.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            metrics = rec.get("metrics", {})
            if isinstance(metrics, dict):
                latest = {
                    str(key): float(value)
                    for key, value in metrics.items()
                    if isinstance(value, (int, float))
                }
    return latest


def plot_performance_decay(log_path: Path | None = None, out_path: Path | None = None) -> Path:
    """Plot accuracy/FPR over evaluation runs."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cfg.ensure_dirs()
    log_path = log_path or cfg.EVAL_LOG_PATH
    out_path = out_path or cfg.FIGURES_DIR / "performance_decay.png"
    if not log_path.exists():
        return out_path

    accs, fprs = [], []
    with log_path.open() as f:
        for line in f:
            rec = json.loads(line)
            m = rec.get("metrics", {})
            if "accuracy" in m:
                accs.append(m["accuracy"])
            if "fpr" in m:
                fprs.append(m["fpr"])

    fig, ax1 = plt.subplots(figsize=(8, 4))
    runs = range(1, len(accs) + 1)
    if accs:
        ax1.plot(runs, accs, "b-o", label="Accuracy")
    ax1.set_xlabel("Evaluation run")
    ax1.set_ylabel("Accuracy")
    ax1.set_title("TESSERACT temporal performance decay")
    if fprs:
        ax2 = ax1.twinx()
        ax2.plot(runs, fprs, "r--s", label="FPR")
        ax2.set_ylabel("FPR")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    return out_path


def _historical_metric_values(metric_name: str, log_path: Path | None = None) -> list[float]:
    log_path = log_path or cfg.EVAL_LOG_PATH
    if not log_path.exists():
        return []
    values: list[float] = []
    with log_path.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            value = rec.get("metrics", {}).get(metric_name)
            if isinstance(value, (int, float)):
                values.append(float(value))
    return values


def compute_aut(values: list[float]) -> float:
    """Area Under Time — trapezoidal integral normalized by steps."""
    if len(values) < 2:
        return float(values[0]) if values else 0.0
    return float(np.trapz(values, dx=1.0) / (len(values) - 1))

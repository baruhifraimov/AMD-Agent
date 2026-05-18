"""TESSERACT temporal evaluation — chronological train/val/test splits."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

import src.config as cfg
import src.db.tracker as db
from src.ml.classifier import fit_threshold, load_bundle, predict_proba
from src.ml.features import features_to_vector

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
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "accuracy": acc,
        "precision": float(prec),
        "recall": float(rec),
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
    rows = tracker.fetch_labeled_with_features()
    if len(rows) < 5:
        logger.warning("Insufficient samples for TESSERACT eval: %d", len(rows))
        return {}

    X = np.vstack([features_to_vector(r["features"]) for r in rows])
    y = np.array([int(r["label"]) for r in rows], dtype=int)
    n = len(y)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))

    bundle = load_bundle()
    if bundle is None:
        return {}

    model = bundle["model"]
    threshold = fit_threshold(y[train_end:val_end], predict_proba(model, X[train_end:val_end]))
    test_scores = predict_proba(model, X[val_end:])
    y_test = y[val_end:]
    y_pred = (test_scores >= threshold).astype(int)
    metrics = compute_metrics(y_test, y_pred)
    metrics["threshold"] = threshold
    metrics["target_fpr"] = cfg.TARGET_FPR
    metrics["aut"] = compute_aut(_historical_metric_values("accuracy") + [metrics["accuracy"]])
    return metrics


def append_eval_log(metrics: dict[str, float], path: Path | None = None) -> None:
    cfg.ensure_dirs()
    p = path or cfg.EVAL_LOG_PATH
    record = {"metrics": metrics}
    with p.open("a") as f:
        f.write(json.dumps(record) + "\n")


def plot_performance_decay(log_path: Path | None = None, out_path: Path | None = None) -> Path:
    """Plot accuracy/FPR over evaluation runs."""
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

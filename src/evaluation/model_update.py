"""Before/after evaluation for production model updates."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

import src.config as cfg
import src.db.tracker as db
from src.evaluation.tesseract import compute_metrics
from src.log import PHASE_EVAL, get_logger, phase_log
from src.ml.classifier import (
    build_training_arrays,
    model_bundle_ready,
    score_feature_matrix,
)
from src.ml.splits import temporal_split

logger = get_logger(__name__)

METRIC_KEYS = ("accuracy", "precision", "recall", "fpr")


def evaluate_bundle_on_current_holdout(
    bundle: dict[str, Any] | None,
    tracker: db.MalwareTracker | None = None,
    *,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> dict[str, float]:
    """Evaluate one production bundle on the latest chronological test split."""
    tracker = tracker or db.get_tracker()
    holdout = _current_holdout(tracker, train_ratio=train_ratio, val_ratio=val_ratio)
    if holdout is None:
        return {}
    X_test, y_test, _health = holdout
    return _evaluate_bundle_on_holdout(bundle, X_test, y_test)


def build_model_update_record(
    *,
    trigger: str,
    previous_bundle: dict[str, Any] | None,
    updated_bundle: dict[str, Any] | None,
    model_version: str,
    tracker: db.MalwareTracker | None = None,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> dict[str, Any]:
    """Build a JSON-safe previous-vs-updated production model record."""
    tracker = tracker or db.get_tracker()
    health = tracker.temporal_split_health(train_ratio=train_ratio, val_ratio=val_ratio)
    holdout = _holdout_summary(health)
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "model_update_comparison",
        "trigger": trigger,
        "baseline_type": "previous_model",
        "model_version": model_version or str((updated_bundle or {}).get("model_version", "")),
        "previous_metrics": {},
        "updated_metrics": {},
        "delta_metrics": {},
        "holdout": holdout,
        "status": "skipped_unhealthy_holdout",
    }
    if not bool(health.get("healthy")):
        record["skip_reason"] = str(health.get("reason") or "unhealthy_temporal_split")
        return record

    X, y, _hashes = build_training_arrays(tracker)
    _X_train, _y_train, _X_val, _y_val, X_test, y_test = temporal_split(
        X,
        y,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
    )
    previous_metrics = _evaluate_bundle_on_holdout(previous_bundle, X_test, y_test)
    updated_metrics = _evaluate_bundle_on_holdout(updated_bundle, X_test, y_test)
    record["previous_metrics"] = previous_metrics
    record["updated_metrics"] = updated_metrics
    record["delta_metrics"] = _metric_delta(previous_metrics, updated_metrics)
    record["status"] = "ok" if previous_metrics else "baseline_created"
    return record


def append_model_update_log(record: dict[str, Any], path: Path | None = None) -> None:
    """Append one model update comparison record to JSONL."""
    cfg.ensure_dirs()
    p = path or cfg.MODEL_UPDATE_LOG_PATH
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def log_model_update_summary(record: dict[str, Any]) -> None:
    """Write a compact before/after comparison to the runtime log."""
    status = str(record.get("status", ""))
    trigger = str(record.get("trigger", ""))
    if status == "skipped_unhealthy_holdout":
        phase_log(
            logger,
            PHASE_EVAL,
            "Model update comparison skipped trigger=%s reason=%s holdout=%s",
            trigger,
            record.get("skip_reason", "unhealthy_temporal_split"),
            record.get("holdout", {}),
            level="warning",
        )
        return

    updated = record.get("updated_metrics") or {}
    if status == "baseline_created":
        phase_log(
            logger,
            PHASE_EVAL,
            "Model baseline recorded trigger=%s version=%s metrics=%s",
            trigger,
            record.get("model_version", ""),
            _format_metrics(updated),
        )
        return

    previous = record.get("previous_metrics") or {}
    delta = record.get("delta_metrics") or {}
    phase_log(
        logger,
        PHASE_EVAL,
        "Model update comparison trigger=%s version=%s %s",
        trigger,
        record.get("model_version", ""),
        _format_before_after(previous, updated, delta),
    )


def record_model_update_comparison(
    *,
    trigger: str,
    previous_bundle: dict[str, Any] | None,
    updated_bundle: dict[str, Any] | None,
    model_version: str,
    tracker: db.MalwareTracker | None = None,
) -> dict[str, Any]:
    """Build, persist, and log one model update comparison record."""
    record = build_model_update_record(
        trigger=trigger,
        previous_bundle=previous_bundle,
        updated_bundle=updated_bundle,
        model_version=model_version,
        tracker=tracker,
    )
    append_model_update_log(record)
    log_model_update_summary(record)
    return record


def _current_holdout(
    tracker: db.MalwareTracker,
    *,
    train_ratio: float,
    val_ratio: float,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]] | None:
    health = tracker.temporal_split_health(train_ratio=train_ratio, val_ratio=val_ratio)
    if not bool(health.get("healthy")):
        return None
    X, y, _hashes = build_training_arrays(tracker)
    _X_train, _y_train, _X_val, _y_val, X_test, y_test = temporal_split(
        X,
        y,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
    )
    return X_test, y_test, health


def _evaluate_bundle_on_holdout(
    bundle: dict[str, Any] | None,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict[str, float]:
    if bundle is None or not model_bundle_ready(bundle) or len(y_test) == 0:
        return {}
    if len(np.unique(y_test)) < 2:
        return {}
    threshold = float(bundle.get("threshold", 0.5))
    scores = score_feature_matrix(bundle, X_test)
    y_pred = (scores >= threshold).astype(int)
    metrics = compute_metrics(y_test, y_pred)
    metrics["threshold"] = threshold
    metrics["support"] = float(len(y_test))
    metrics["test_benign"] = float(np.sum(y_test == 0))
    metrics["test_malware"] = float(np.sum(y_test == 1))
    return metrics


def _metric_delta(
    previous: dict[str, float],
    updated: dict[str, float],
) -> dict[str, float]:
    return {
        key: float(updated[key] - previous[key])
        for key in METRIC_KEYS
        if key in previous and key in updated
    }


def _holdout_summary(health: dict[str, Any]) -> dict[str, Any]:
    return {
        "support": int(health.get("support", 0) or 0),
        "test_benign": int(health.get("test_benign", 0) or 0),
        "test_malware": int(health.get("test_malware", 0) or 0),
        "healthy": bool(health.get("healthy")),
    }


def _format_metrics(metrics: dict[str, Any]) -> str:
    parts = []
    for key in METRIC_KEYS:
        if key in metrics:
            parts.append(f"{key}={float(metrics[key]):.4f}")
    return " ".join(parts) if parts else "n/a"


def _format_before_after(
    previous: dict[str, Any],
    updated: dict[str, Any],
    delta: dict[str, Any],
) -> str:
    parts = []
    for key in METRIC_KEYS:
        if key in previous and key in updated:
            parts.append(
                f"{key}={float(previous[key]):.4f}->{float(updated[key]):.4f}"
                f" ({float(delta.get(key, 0.0)):+.4f})"
            )
    return " ".join(parts) if parts else "metrics=n/a"

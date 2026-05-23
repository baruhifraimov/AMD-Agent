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


def build_strict_temporal_holdout(
    tracker: db.MalwareTracker | None = None,
    *,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> dict[str, Any]:
    """Build the exact temporal holdout to exclude from training and evaluate on."""
    tracker = tracker or db.get_tracker()
    X, y, hashes = build_training_arrays(tracker)
    n = len(y)
    _X_train, _y_train, _X_val, _y_val, X_test, y_test = temporal_split(
        X,
        y,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
    )
    holdout_start = n - len(y_test)
    holdout_hashes = list(hashes[holdout_start:])
    test_benign = int(np.sum(y_test == 0))
    test_malware = int(np.sum(y_test == 1))
    healthy = n >= 5 and len(y_test) > 0 and test_benign > 0 and test_malware > 0
    reason = ""
    if n < 5:
        reason = "insufficient"
    elif len(y_test) == 0:
        reason = "empty_holdout"
    elif not healthy:
        reason = "single_class_holdout"
    return {
        "evaluation_mode": "strict_temporal_holdout",
        "train_ratio": train_ratio,
        "val_ratio": val_ratio,
        "x": X_test,
        "y": y_test,
        "hashes": holdout_hashes,
        "summary": {
            "support": int(n),
            "holdout_support": int(len(y_test)),
            "test_benign": test_benign,
            "test_malware": test_malware,
            "healthy": healthy,
        },
        "healthy": healthy,
        "reason": reason,
    }


def build_model_update_record(
    *,
    trigger: str,
    previous_bundle: dict[str, Any] | None,
    updated_bundle: dict[str, Any] | None,
    model_version: str,
    tracker: db.MalwareTracker | None = None,
    holdout: dict[str, Any] | None = None,
    holdout_excluded_from_training: bool = False,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> dict[str, Any]:
    """Build a JSON-safe previous-vs-updated production model record."""
    tracker = tracker or db.get_tracker()
    strict_holdout = holdout or build_strict_temporal_holdout(
        tracker,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
    )
    holdout_summary = _holdout_summary(strict_holdout)
    previous_model_strict = _bundle_strict(previous_bundle)
    updated_model_strict = _bundle_strict(updated_bundle)
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "model_update_comparison",
        "trigger": trigger,
        "baseline_type": "previous_model",
        "evaluation_mode": "strict_temporal_holdout",
        "holdout_excluded_from_training": bool(holdout_excluded_from_training),
        "previous_model_strict": previous_model_strict,
        "updated_model_strict": updated_model_strict,
        "model_version": model_version or str((updated_bundle or {}).get("model_version", "")),
        "previous_metrics": {},
        "updated_metrics": {},
        "delta_metrics": {},
        "holdout": holdout_summary,
        "status": "skipped_unhealthy_holdout",
    }
    if not bool(strict_holdout.get("healthy")):
        record["skip_reason"] = str(strict_holdout.get("reason") or "unhealthy_temporal_holdout")
        return record

    X_test = strict_holdout["x"]
    y_test = strict_holdout["y"]
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
            "Model baseline recorded trigger=%s version=%s strict=%s metrics=%s",
            trigger,
            record.get("model_version", ""),
            record.get("updated_model_strict", False),
            _format_metrics(updated),
        )
        return

    previous = record.get("previous_metrics") or {}
    delta = record.get("delta_metrics") or {}
    if not bool(record.get("previous_model_strict", False)):
        phase_log(
            logger,
            PHASE_EVAL,
            "Model update baseline is not strict; previous model may have seen this holdout",
            level="warning",
        )
    phase_log(
        logger,
        PHASE_EVAL,
        "Model update comparison trigger=%s version=%s previous_strict=%s updated_strict=%s %s",
        trigger,
        record.get("model_version", ""),
        record.get("previous_model_strict", False),
        record.get("updated_model_strict", False),
        _format_before_after(previous, updated, delta),
    )


def record_model_update_comparison(
    *,
    trigger: str,
    previous_bundle: dict[str, Any] | None,
    updated_bundle: dict[str, Any] | None,
    model_version: str,
    tracker: db.MalwareTracker | None = None,
    holdout: dict[str, Any] | None = None,
    holdout_excluded_from_training: bool = False,
) -> dict[str, Any]:
    """Build, persist, and log one model update comparison record."""
    record = build_model_update_record(
        trigger=trigger,
        previous_bundle=previous_bundle,
        updated_bundle=updated_bundle,
        model_version=model_version,
        tracker=tracker,
        holdout=holdout,
        holdout_excluded_from_training=holdout_excluded_from_training,
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


def _holdout_summary(holdout: dict[str, Any]) -> dict[str, Any]:
    summary = dict(holdout.get("summary") or {})
    return {
        "support": int(summary.get("support", 0) or 0),
        "holdout_support": int(summary.get("holdout_support", 0) or 0),
        "test_benign": int(summary.get("test_benign", 0) or 0),
        "test_malware": int(summary.get("test_malware", 0) or 0),
        "healthy": bool(summary.get("healthy")),
        "hashes": list(holdout.get("hashes") or []),
    }


def _bundle_strict(bundle: dict[str, Any] | None) -> bool:
    if not isinstance(bundle, dict):
        return False
    return (
        bundle.get("evaluation_mode") == "strict_temporal_holdout"
        and bundle.get("strict_holdout_excluded") is True
    )


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

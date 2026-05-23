"""Model retrain node — MADAR replay and LightGBM update."""

from __future__ import annotations

from datetime import datetime, timezone

import src.db.tracker as db
from src.config import allow_local_benign
from src.log import PHASE_RETRAIN, get_logger, phase_log, task_status
from src.ml.classifier import ingest_benign_corpus
from src.ml.madar import madar_retrain
from src.state import AgentState

logger = get_logger(__name__)


def _valid_label(label: object) -> int | None:
    if label in (0, 1):
        return int(label)
    return None


def _force_feature_reselection(drift_stats: dict[str, float]) -> bool:
    """Re-rank features on stronger drift, otherwise reuse the previous selected set."""
    mean_shift = float(drift_stats.get("mean_shift", 0.0) or 0.0)
    corr_shift = float(drift_stats.get("corr_shift", 0.0) or 0.0)
    return mean_shift >= 3.0 or corr_shift >= 0.7


def _make_model_version() -> str:
    return f"v_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"


def model_retrain(state: AgentState) -> dict:
    trigger = "drift_detected" if state.drift_detected else "threshold_retrain"
    model_version = _make_model_version()

    tracker = db.get_tracker()
    if allow_local_benign():
        ingest_benign_corpus(tracker)
    rows = tracker.fetch_labeled_with_features()

    historical_features: list[dict] = []
    historical_labels: list[int] = []
    historical_families: list[str] = []
    new_hashes = {item.get("sha256") for item in state.new_labeled_batch}

    for row in rows:
        feats = row.get("features")
        if not feats:
            continue
        sha = row["sha256"]
        if sha in new_hashes:
            continue
        label = _valid_label(row.get("label"))
        if label is None:
            continue
        historical_features.append(feats)
        historical_labels.append(label)
        historical_families.append(row.get("malware_family") or "unknown")

    new_features: list[dict] = []
    new_labels: list[int] = []
    for item in state.new_labeled_batch:
        label = _valid_label(item.get("label"))
        if label is None:
            continue
        new_features.append(dict(item))
        new_labels.append(label)

    task_id = tracker.create_task(
        trigger=trigger,
        sample_count=len(new_hashes),
        model_version=model_version,
    )
    for h in new_hashes:
        tracker.update_sample_task(h, task_id)

    if not new_features and state.new_labeled_batch:
        logger.warning(
            "[%s] MADAR retrain skipped: %s batch had %d sample(s) but none with verified labels",
            PHASE_RETRAIN,
            trigger,
            len(state.new_labeled_batch),
        )
        return _retrain_skipped(state, historical_features, new_features, trigger)

    try:
        from src.ml.classifier import load_bundle

        feature_reselection = _force_feature_reselection(state.drift_stats)
        with task_status(PHASE_RETRAIN, f"MADAR retrain ({trigger})"):
            bundle = madar_retrain(
                historical_features,
                new_features,
                historical_labels,
                new_labels,
                historical_families=historical_families,
                force_feature_reselection=feature_reselection,
                init_model=load_bundle(),
            )
    except ValueError as exc:
        logger.warning("[%s] MADAR retrain skipped: %s", PHASE_RETRAIN, exc)
        return _retrain_skipped(state, historical_features, new_features, trigger)

    if bundle is None:
        logger.warning("[%s] MADAR retrain skipped; no reusable model bundle is available", PHASE_RETRAIN)
        return _retrain_skipped(state, historical_features, new_features, trigger)

    trained_count = tracker.mark_all_trained(task_id)
    phase_log(
        logger,
        PHASE_RETRAIN,
        "Complete trigger=%s version=%s threshold=%.4f trained=%d",
        trigger,
        model_version,
        bundle.get("threshold", 0.5),
        trained_count,
    )

    return {
        "drift_detected": False,
        "threshold_retrain": False,
        "new_labeled_batch": [],
        "evaluation_metrics": {
            **state.evaluation_metrics,
            "retrained": 1.0,
            "retrain_trigger": trigger,
            "model_version": model_version,
            "replay_size": float(len(historical_features)),
            "new_batch_size": float(len(new_features)),
            "feature_reselection": 1.0 if feature_reselection else 0.0,
        },
    }


def _retrain_skipped(
    state: AgentState,
    historical_features: list[dict],
    new_features: list[dict],
    trigger: str = "drift_detected",
) -> dict:
    return {
        "drift_detected": False,
        "threshold_retrain": False,
        "new_labeled_batch": [],
        "evaluation_metrics": {
            **state.evaluation_metrics,
            "retrained": 0.0,
            "retrain_trigger": trigger,
            "retrain_skipped_single_class": 1.0,
            "replay_size": float(len(historical_features)),
            "new_batch_size": float(len(new_features)),
        },
    }

"""Model retrain node — MADAR replay and LightGBM update."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.config import allow_local_benign
from src.ml.classifier import ingest_benign_corpus
from src.ml.madar import madar_retrain
from src.state import AgentState

logger = logging.getLogger(__name__)


def _valid_label(label: object) -> int | None:
    if label in (0, 1):
        return int(label)
    return None


def model_retrain(state: AgentState) -> dict:
    tracker = db.get_tracker()
    if allow_local_benign():
        ingest_benign_corpus(tracker)
    rows = tracker.fetch_labeled_with_features()

    historical_features: list[dict] = []
    historical_labels: list[int] = []
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

    new_features: list[dict] = []
    new_labels: list[int] = []
    for item in state.new_labeled_batch:
        label = _valid_label(item.get("label"))
        if label is None:
            continue
        new_features.append(dict(item))
        new_labels.append(label)

    if not new_features and state.new_labeled_batch:
        logger.warning(
            "MADAR retrain skipped: drift batch had %d sample(s) but none with verified labels",
            len(state.new_labeled_batch),
        )
        return _retrain_skipped(state, historical_features, new_features)

    try:
        bundle = madar_retrain(
            historical_features,
            new_features,
            historical_labels,
            new_labels,
        )
    except ValueError as exc:
        logger.warning("MADAR retrain skipped: %s", exc)
        return _retrain_skipped(state, historical_features, new_features)

    if bundle is None:
        logger.warning("MADAR retrain skipped; no reusable model bundle is available")
        return _retrain_skipped(state, historical_features, new_features)

    logger.info("MADAR retrain complete; threshold=%.4f", bundle.get("threshold", 0.5))

    return {
        "drift_detected": False,
        "new_labeled_batch": [],
        "evaluation_metrics": {
            **state.evaluation_metrics,
            "retrained": 1.0,
            "replay_size": float(len(historical_features)),
            "new_batch_size": float(len(new_features)),
        },
    }


def _retrain_skipped(
    state: AgentState,
    historical_features: list[dict],
    new_features: list[dict],
) -> dict:
    return {
        "drift_detected": False,
        "new_labeled_batch": [],
        "evaluation_metrics": {
            **state.evaluation_metrics,
            "retrained": 0.0,
            "retrain_skipped_single_class": 1.0,
            "replay_size": float(len(historical_features)),
            "new_batch_size": float(len(new_features)),
        },
    }

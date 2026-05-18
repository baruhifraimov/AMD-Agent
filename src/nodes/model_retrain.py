"""Model retrain node — MADAR replay + LightGBM update."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.config import allow_local_benign
from src.ml.classifier import ingest_benign_corpus, load_bundle
from src.ml.madar import madar_retrain
from src.state import AgentState

logger = logging.getLogger(__name__)


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
        historical_features.append(feats)
        historical_labels.append(int(row.get("label", 1)))

    new_features = [dict(f) for f in state.new_labeled_batch]
    new_labels = [int(f.get("label", 1)) for f in state.new_labeled_batch]

    bundle = madar_retrain(
        historical_features,
        new_features,
        historical_labels,
        new_labels,
    )
    if bundle is None:
        logger.warning("MADAR retrain skipped; no reusable model bundle is available")
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

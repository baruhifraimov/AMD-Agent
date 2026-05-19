"""Classifier inference node — LightGBM prediction with tuned threshold."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.config import MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE
from src.ml.classifier import (
    cold_start_train,
    load_bundle,
    model_bundle_ready,
    score_samples,
)
from src.state import AgentState

logger = logging.getLogger(__name__)


def classifier_inference(state: AgentState) -> dict:
    tracker = db.get_tracker()
    counts = tracker.count_by_label()
    bundle = load_bundle()
    if bundle is not None and not model_bundle_ready(bundle):
        logger.info(
            "Existing model bundle is below current bootstrap targets; "
            "awaiting malware=%d/%d benign=%d/%d",
            counts.get(1, 0),
            MIN_TRAIN_MALWARE,
            counts.get(0, 0),
            MIN_TRAIN_BENIGN,
        )
        bundle = None
    if bundle is None:
        bundle = cold_start_train(tracker)

    metrics: dict[str, float] = dict(state.evaluation_metrics)
    predictions: dict[str, float] = dict(state.predictions)

    if bundle is None:
        metrics["model_ready"] = 0.0
        logger.info("Model not ready; awaiting more training samples")
        return {"predictions": predictions, "evaluation_metrics": metrics}

    metrics["model_ready"] = 1.0
    hashes = [f.get("sha256", "") for f in state.feature_vectors if f.get("sha256")]
    feature_dicts = [f for f in state.feature_vectors if f.get("sha256")]
    scores = score_samples(bundle, feature_dicts, hashes)
    threshold = float(bundle.get("threshold", 0.5))

    for sha, prob in scores.items():
        predictions[sha] = prob
        tracker.update_prediction(sha, prob)

    metrics["decision_threshold"] = threshold
    metrics["mean_score"] = float(sum(scores.values()) / len(scores)) if scores else 0.0
    logger.info("Scored %d samples (threshold=%.4f)", len(scores), threshold)
    return {"predictions": predictions, "evaluation_metrics": metrics}

"""Drift monitor node — River ADWIN on section entropy."""

from __future__ import annotations

import logging

from src.ml.drift import DriftMonitor
from src.state import AgentState

logger = logging.getLogger(__name__)


def drift_monitor(state: AgentState) -> dict:
    monitor = DriftMonitor()
    drift_detected = False
    labeled_batch: list[dict] = []

    for feats, entropy in zip(state.feature_vectors, state.section_entropies):
        if monitor.update(entropy):
            drift_detected = True
        if drift_detected:
            row = dict(feats)
            row["label"] = 1
            labeled_batch.append(row)

    if drift_detected:
        logger.warning("Concept drift detected on %d samples", len(labeled_batch))

    return {
        "drift_detected": drift_detected,
        "new_labeled_batch": labeled_batch if drift_detected else [],
    }

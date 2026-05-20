"""Drift monitor node — River ADWIN with verified per-sample labeling."""

from __future__ import annotations

import logging

from src.ml.services import DriftMonitorService
from src.state import AgentState

logger = logging.getLogger(__name__)


def drift_monitor(state: AgentState) -> dict:
    service = DriftMonitorService()
    drift_detected, labeled_batch = service.update_batch(
        state.feature_vectors,
        state.section_entropies,
        hash_metadata=state.hash_metadata,
    )

    if drift_detected:
        logger.warning("Concept drift detected on %d verified sample(s)", len(labeled_batch))

    return {
        "drift_detected": drift_detected,
        "new_labeled_batch": labeled_batch,
    }

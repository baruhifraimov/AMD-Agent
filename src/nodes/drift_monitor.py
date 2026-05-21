"""Drift monitor node — River ADWIN with verified per-sample labeling."""

from __future__ import annotations

import logging

from src.collection.context import build_collection_context
from src.ml.services import DriftMonitorService
from src.state import AgentState

logger = logging.getLogger(__name__)


def drift_monitor(state: AgentState) -> dict:
    ctx = build_collection_context()
    if state.collection_phase == "bootstrap" or ctx.phase == "bootstrap":
        logger.info("Drift monitor skipped: collection phase is bootstrap")
        return {
            "drift_detected": False,
            "new_labeled_batch": [],
        }

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

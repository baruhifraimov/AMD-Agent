"""Drift monitor node — River ADWIN with verified per-sample labeling."""

from __future__ import annotations

import src.db.tracker as db
from src.collection.context import build_collection_context
from src.config import THRESHOLD_RETRAIN_MIN_NEW_SAMPLES
from src.log import PHASE_DRIFT, get_logger, phase_log
from src.ml.services import DriftMonitorService
from src.state import AgentState

logger = get_logger(__name__)


def drift_monitor(state: AgentState) -> dict:
    ctx = build_collection_context()
    if state.collection_phase == "bootstrap" or ctx.phase == "bootstrap":
        phase_log(logger, PHASE_DRIFT, "Skipped (bootstrap phase)")
        return {
            "drift_detected": False,
            "threshold_retrain": False,
            "new_labeled_batch": [],
            "pending_drift_log": False,
            "drift_stats": {},
            "drift_pre_metrics": {},
        }

    service = DriftMonitorService()
    drift_detected, labeled_batch, drift_stats = service.update_batch(
        state.feature_vectors,
        state.section_entropies,
        hash_metadata=state.hash_metadata,
    )

    out: dict = {
        "drift_detected": drift_detected,
        "threshold_retrain": False,
        "new_labeled_batch": labeled_batch,
        "drift_stats": drift_stats,
        "pending_drift_log": False,
        "drift_pre_metrics": {},
    }

    if drift_detected:
        logger.warning(
            "[%s] Concept drift detected: labeled_batch=%d",
            PHASE_DRIFT,
            len(labeled_batch),
        )
        from src.evaluation.tesseract import latest_eval_metrics

        out["drift_pre_metrics"] = latest_eval_metrics()
        out["pending_drift_log"] = True
        out["need_new_sources"] = True
    else:
        tracker = db.get_tracker()
        untrained_count = tracker.count_untrained_with_features()
        if untrained_count >= THRESHOLD_RETRAIN_MIN_NEW_SAMPLES:
            untrained_samples = tracker.fetch_untrained_with_features()
            out["threshold_retrain"] = True
            out["new_labeled_batch"] = untrained_samples
            phase_log(
                logger,
                PHASE_DRIFT,
                "Threshold retrain: %d untrained samples (threshold=%d)",
                untrained_count,
                THRESHOLD_RETRAIN_MIN_NEW_SAMPLES,
            )
        else:
            phase_log(logger, PHASE_DRIFT, "No drift; %d samples in batch", len(state.feature_vectors))

    return out

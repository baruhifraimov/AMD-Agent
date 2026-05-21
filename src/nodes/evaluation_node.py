"""LangGraph evaluation node — TESSERACT metrics and drift evidence logging."""

from __future__ import annotations

import logging

from src.collection.context import build_collection_context
from src.evaluation.drift_log import append_drift_log, build_drift_record
from src.ml.classifier import load_bundle, model_bundle_ready
from src.state import AgentState

logger = logging.getLogger(__name__)


def _should_warn_empty_eval(state: AgentState) -> bool:
    if state.collection_phase == "bootstrap":
        return False
    ctx = build_collection_context()
    if ctx.phase == "bootstrap":
        return False
    return model_bundle_ready(load_bundle())


def evaluation_node(state: AgentState) -> dict:
    """Evaluate model performance and log artifacts for the final report."""
    try:
        from src.evaluation.tesseract import append_eval_log, plot_performance_decay, run_tesseract_eval

        logger.info("Running post-operation evaluation...")
        metrics = run_tesseract_eval()
        merged: dict[str, float] = {**state.evaluation_metrics, **metrics}

        if metrics:
            append_eval_log(metrics)
            plot_performance_decay()
            logger.info("TESSERACT eval: %s", metrics)
        elif _should_warn_empty_eval(state):
            logger.warning(
                "TESSERACT eval returned no metrics (steady phase, model ready); "
                "check labeled sample count and class balance"
            )

        out: dict = {"evaluation_metrics": merged}

        if state.pending_drift_log:
            record = build_drift_record(state, post_metrics=metrics)
            append_drift_log(record)
            logger.info("Drift event logged to drift_log.jsonl")
            out["pending_drift_log"] = False

        return out
    except Exception as exc:
        logger.error("Critical: Evaluation failed: %s", exc)
        raise

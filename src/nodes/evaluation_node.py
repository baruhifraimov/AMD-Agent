"""LangGraph evaluation node — TESSERACT metrics and drift evidence logging."""

from __future__ import annotations

import json
import logging
from typing import Any

from src.collection.context import build_collection_context
from src.config import EVAL_EVERY_RUNS, EVAL_SKIP_BOOTSTRAP, EVAL_STATE_PATH, ensure_dirs
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


def _load_eval_state() -> dict[str, Any]:
    if not EVAL_STATE_PATH.exists():
        return {"runs": 0}
    try:
        data = json.loads(EVAL_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("Evaluation state unreadable; resetting: %s", EVAL_STATE_PATH)
        return {"runs": 0}
    if not isinstance(data, dict):
        return {"runs": 0}
    return {"runs": int(data.get("runs", 0) or 0)}


def _save_eval_state(data: dict[str, Any]) -> None:
    ensure_dirs()
    EVAL_STATE_PATH.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")


def _next_eval_run() -> int:
    data = _load_eval_state()
    run_count = int(data.get("runs", 0)) + 1
    data["runs"] = run_count
    _save_eval_state(data)
    return run_count


def _collection_phase(state: AgentState) -> str:
    if state.collection_phase:
        return state.collection_phase
    return build_collection_context().phase


def _forced_eval(state: AgentState) -> bool:
    return state.pending_drift_log or "retrained" in state.evaluation_metrics


def _should_run_eval(state: AgentState) -> tuple[bool, int | None, str, str]:
    phase = _collection_phase(state)
    if _forced_eval(state):
        return True, None, phase, "forced"
    if EVAL_SKIP_BOOTSTRAP and phase == "bootstrap":
        return False, None, phase, "bootstrap"

    run_count = _next_eval_run()
    if run_count % EVAL_EVERY_RUNS == 0:
        return True, run_count, phase, "periodic"
    return False, run_count, phase, "interval"


def evaluation_node(state: AgentState) -> dict:
    """Evaluate model performance and log artifacts for the final report."""
    should_run, run_count, phase, reason = _should_run_eval(state)
    if not should_run:
        if run_count is None:
            logger.info("Evaluation skipped: phase=%s reason=%s", phase, reason)
        else:
            logger.info(
                "Evaluation skipped: run=%d interval=%d phase=%s",
                run_count,
                EVAL_EVERY_RUNS,
                phase,
            )
        return {"evaluation_metrics": state.evaluation_metrics}

    metrics: dict[str, float] = {}
    merged: dict[str, float] = dict(state.evaluation_metrics)
    try:
        from src.evaluation.tesseract import append_eval_log, plot_performance_decay, run_tesseract_eval

        logger.info("Running post-operation evaluation (reason=%s)", reason)
        metrics = run_tesseract_eval()
        merged = {**state.evaluation_metrics, **metrics}

        if metrics:
            append_eval_log(metrics)
            plot_performance_decay()
            logger.info("TESSERACT eval: %s", metrics)
        elif _should_warn_empty_eval(state):
            logger.warning(
                "TESSERACT eval returned no metrics (steady phase, model ready); "
                "check labeled sample count and class balance"
            )
    except Exception as exc:
        logger.warning("Evaluation failed; continuing without TESSERACT metrics: %s", exc)
        merged["evaluation_error"] = 1.0

    out: dict = {"evaluation_metrics": merged}

    if state.pending_drift_log:
        try:
            log_state = state.model_copy(update={"evaluation_metrics": merged})
            record = build_drift_record(log_state, post_metrics=metrics)
            append_drift_log(record)
            logger.info("Drift event logged to drift_log.jsonl")
            out["pending_drift_log"] = False
        except Exception as exc:
            logger.warning("Drift event logging failed; continuing: %s", exc)
            out["pending_drift_log"] = True

    return out

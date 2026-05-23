"""LangGraph evaluation node — TESSERACT metrics and drift evidence logging."""

from __future__ import annotations

import json
from typing import Any

from src.collection.context import build_collection_context
from src.config import EVAL_EVERY_RUNS, EVAL_SKIP_BOOTSTRAP, EVAL_STATE_PATH, ensure_dirs
from src.evaluation.drift_log import append_drift_log, build_drift_record
from src.evaluation.training_history import (
    DELTA_METRIC_KEYS,
    append_history,
    compute_delta_pct,
    read_last_history,
)
from src.log import PHASE_EVAL, PHASE_RETRAIN, get_logger, phase_log, task_status, vlog
from src.ml.classifier import load_bundle, model_bundle_ready
from src.state import AgentState

logger = get_logger(__name__)


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
        logger.warning("[%s] Evaluation state unreadable; resetting: %s", PHASE_EVAL, EVAL_STATE_PATH)
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


def _current_scalar_metrics(metrics: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    for key in DELTA_METRIC_KEYS:
        value = metrics.get(key)
        if isinstance(value, (int, float)):
            out[key] = float(value)
    return out


def _record_training_history(merged: dict[str, Any]) -> dict[str, Any]:
    """Append per-retrain record to training_history.jsonl and log improvement summary."""
    from datetime import datetime, timezone

    current = _current_scalar_metrics(merged)
    if not current:
        return {}

    previous_record = read_last_history()
    previous = previous_record.get("metrics", {}) if previous_record else {}
    delta_pct = compute_delta_pct(current, previous)
    improved = delta_pct.get("accuracy", 0.0) >= 0.0

    retrain_count = int(merged.get("retrain_count", 0) or 0)
    trigger = str(merged.get("retrain_trigger") or "unknown")
    model_version = str(merged.get("model_version") or "")
    task_id = int(merged.get("task_id", 0) or 0)
    sample_count = int(merged.get("new_batch_size", 0) or 0)

    record = {
        "retrain_count": retrain_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trigger": trigger,
        "model_version": model_version,
        "task_id": task_id,
        "sample_count": sample_count,
        "metrics": current,
        "previous": {k: float(v) for k, v in previous.items() if isinstance(v, (int, float))},
        "delta_pct": delta_pct,
        "improved": improved,
    }
    append_history(record)

    prev_acc = float(previous.get("accuracy", 0.0)) if previous else 0.0
    curr_acc = current.get("accuracy", 0.0)
    pct = delta_pct.get("accuracy", 0.0)
    sign = "+" if pct >= 0 else ""
    label = "IMPROVED" if improved else "REGRESSION"
    phase_log(
        logger,
        PHASE_RETRAIN,
        "Retrain #%d [%s] | acc %.4f -> %.4f (%s%.2f%%) | %s",
        retrain_count,
        trigger,
        prev_acc,
        curr_acc,
        sign,
        pct,
        label,
    )
    if not improved:
        logger.warning(
            "[%s] MODEL REGRESSION — new model worse than previous; review training_history.jsonl",
            PHASE_RETRAIN,
        )

    return {
        "retrain_count": retrain_count,
        "previous_metrics": {k: float(v) for k, v in previous.items() if isinstance(v, (int, float))},
        "delta_metrics": delta_pct,
        "improved": improved,
    }


def evaluation_node(state: AgentState) -> dict:
    """Evaluate model performance and log artifacts for the final report."""
    should_run, run_count, phase, reason = _should_run_eval(state)
    if not should_run:
        if run_count is None:
            phase_log(logger, PHASE_EVAL, "Skipped (%s, phase=%s)", reason, phase)
        else:
            remainder = run_count % EVAL_EVERY_RUNS
            runs_until = EVAL_EVERY_RUNS - remainder if remainder else EVAL_EVERY_RUNS
            phase_log(
                logger,
                PHASE_EVAL,
                "Skipped (next TESSERACT in %d run(s), counter=%d, phase=%s)",
                runs_until,
                run_count,
                phase,
            )
        return {"evaluation_metrics": state.evaluation_metrics}

    metrics: dict[str, float] = {}
    merged: dict[str, float] = dict(state.evaluation_metrics)
    try:
        from src.evaluation.tesseract import append_eval_log, plot_performance_decay, run_tesseract_eval, run_retrograde_eval

        phase_log(logger, PHASE_EVAL, "Running TESSERACT (%s, phase=%s)", reason, phase)
        with task_status(PHASE_EVAL, f"TESSERACT evaluation ({reason})"):
            metrics = run_tesseract_eval()
            retro_metrics = run_retrograde_eval()

        metrics.update(retro_metrics)
        merged = {**state.evaluation_metrics, **metrics}

        if metrics:
            append_eval_log(metrics)
            plot_performance_decay()
            phase_log(logger, PHASE_EVAL, "TESSERACT metrics recorded")
            vlog(logger, "info", "TESSERACT eval detail: %s", metrics)
        elif _should_warn_empty_eval(state):
            logger.warning(
                "[%s] TESSERACT returned no metrics (steady phase, model ready); "
                "check labeled sample count and class balance",
                PHASE_EVAL,
            )
    except Exception as exc:
        logger.warning("[%s] Evaluation failed; continuing: %s", PHASE_EVAL, exc)
        merged["evaluation_error"] = 1.0

    out: dict = {"evaluation_metrics": merged}

    if metrics and merged.get("retrained") == 1.0:
        try:
            history_update = _record_training_history(merged)
            out.update(history_update)
        except Exception as exc:
            logger.warning("[%s] Training history record failed; continuing: %s", PHASE_EVAL, exc)

    if state.pending_drift_log:
        try:
            log_state = state.model_copy(update={"evaluation_metrics": merged})
            record = build_drift_record(log_state, post_metrics=metrics)
            append_drift_log(record)
            phase_log(logger, PHASE_EVAL, "Drift event logged to drift_log.jsonl")
            out["pending_drift_log"] = False
        except Exception as exc:
            logger.warning("[%s] Drift event logging failed; continuing: %s", PHASE_EVAL, exc)
            out["pending_drift_log"] = True

    return out

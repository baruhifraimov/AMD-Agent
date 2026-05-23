"""Explain drift context using Ollama + static PE features."""

from __future__ import annotations

from src.config import ollama_drift_context_report_enabled
from src.llm import summarize_drift_context
from src.log import PHASE_DRIFT, get_logger, phase_log, task_status
from src.state import AgentState

logger = get_logger(__name__)


def explain_drift_context(state: AgentState) -> dict:
    if not ollama_drift_context_report_enabled():
        phase_log(
            logger,
            PHASE_DRIFT,
            "Context report disabled (OLLAMA_DRIFT_CONTEXT_REPORT_ENABLED=False)",
        )
        return {"semantic_report": None}

    with task_status(PHASE_DRIFT, "Summarizing drift context (Ollama)"):
        report = summarize_drift_context(
            drift_stats=state.drift_stats,
            feature_vectors=state.feature_vectors,
            hash_metadata=state.hash_metadata,
        )
    phase_log(logger, PHASE_DRIFT, "Drift context report ready (%d chars)", len(report or ""))
    return {"semantic_report": report}

"""Explain drift context using Ollama + static PE features."""

from __future__ import annotations

from src.llm import summarize_drift_context
from src.state import AgentState


def explain_drift_context(state: AgentState) -> dict:
    report = summarize_drift_context(
        drift_stats=state.drift_stats,
        feature_vectors=state.feature_vectors,
        hash_metadata=state.hash_metadata,
    )
    return {"semantic_report": report}

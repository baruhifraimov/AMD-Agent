"""Source discovery node — delegate to active PE provider."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.collection import build_collection_context, discover_with_fallback
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_discovery(state: AgentState) -> dict:
    tracker = db.get_tracker()
    ctx = build_collection_context(tracker)
    source_names = state.selected_sources or ([state.source_type] if state.source_type else [])
    candidates = discover_with_fallback(
        source_names,
        tracker=tracker,
        ctx=ctx,
        expected_label=state.expected_label,
        cti_queries=state.cti_queries or None,
    )
    return {
        "sample_candidates": [c.to_dict() for c in candidates],
        "expected_label": state.expected_label,
    }

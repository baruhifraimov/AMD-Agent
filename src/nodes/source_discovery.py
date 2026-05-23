"""Source discovery node — delegate to active PE provider."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.collection import (
    build_collection_context,
    discover_active_benign_sources,
    discover_active_malware_sources,
    discover_mixed_sources,
    discover_with_fallback,
)
from src.collection.provider_stats import merge_discovery_stats
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_discovery(state: AgentState) -> dict:
    tracker = db.get_tracker()
    ctx = build_collection_context(tracker)
    source_names = state.selected_sources or ([state.source_type] if state.source_type else [])
    discovery_stats: list[dict] = []
    if state.expected_label == -1:
        candidates = discover_mixed_sources(
            source_names,
            tracker=tracker,
            ctx=ctx,
            limit=None,
            stats=discovery_stats,
        )
    elif state.expected_label == 1 and "malwarebazaar" in source_names:
        candidates = discover_active_malware_sources(
            source_names,
            tracker=tracker,
            ctx=ctx,
            limit=None,
            stats=discovery_stats,
        )
    elif state.expected_label == 0:
        candidates = discover_active_benign_sources(
            source_names,
            tracker=tracker,
            ctx=ctx,
            limit=None,
            stats=discovery_stats,
        )
    else:
        candidates = discover_with_fallback(
            source_names,
            tracker=tracker,
            ctx=ctx,
            expected_label=state.expected_label,
            stats=discovery_stats,
        )
    metrics = dict(state.bootstrap_metrics)
    metrics["discovery"] = discovery_stats
    metrics["discovered_count"] = len(candidates)
    merge_discovery_stats(metrics, discovery_stats)
    if ctx.phase == "bootstrap":
        logger.info(
            "Bootstrap discovery summary: providers=%s discovered=%d fresh=%d returned=%d",
            ",".join(str(s.get("provider", "")) for s in discovery_stats),
            sum(int(s.get("discovered", 0)) for s in discovery_stats),
            sum(int(s.get("fresh", 0)) for s in discovery_stats),
            len(candidates),
        )
    return {
        "sample_candidates": [c.to_dict() for c in candidates],
        "expected_label": state.expected_label,
        "bootstrap_metrics": metrics,
    }

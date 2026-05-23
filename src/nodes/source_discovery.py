"""Source discovery node — delegate to active PE provider."""

from __future__ import annotations

import src.db.tracker as db
from src.collection import (
    build_collection_context,
    discover_active_benign_sources,
    discover_active_malware_sources,
    discover_mixed_sources,
    discover_with_fallback,
)
from src.collection.provider_stats import merge_discovery_stats, summarize_discovery_providers
from src.log import PHASE_DISCOVERY, get_logger, phase_log, task_status, vlog
from src.state import AgentState

logger = get_logger(__name__)


def source_discovery(state: AgentState) -> dict:
    tracker = db.get_tracker()
    ctx = build_collection_context(tracker)
    source_names = state.selected_sources or ([state.source_type] if state.source_type else [])
    discovery_stats: list[dict] = []
    label = state.expected_label
    with task_status(PHASE_DISCOVERY, f"Discovering from {','.join(source_names) or 'default'}"):
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
    fresh = sum(int(s.get("fresh", 0)) for s in discovery_stats)
    discovered = sum(int(s.get("discovered", 0)) for s in discovery_stats)
    sources_summary = summarize_discovery_providers(discovery_stats)
    phase_log(
        logger,
        PHASE_DISCOVERY,
        "Done: %d candidates (label=%d) via %s",
        len(candidates),
        label,
        sources_summary,
    )
    vlog(
        logger,
        "info",
        "Discovery totals: fresh=%d discovered=%d via %s",
        fresh,
        discovered,
        sources_summary,
    )
    return {
        "sample_candidates": [c.to_dict() for c in candidates],
        "expected_label": state.expected_label,
        "bootstrap_metrics": metrics,
    }

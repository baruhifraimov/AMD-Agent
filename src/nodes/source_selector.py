"""Source selector node — choose malware vs benign provider."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.collection import CollectionStrategyFactory, build_collection_context
from src.config import ollama_source_selection_enabled
from src.llm import choose_sources_with_ollama
from src.sources.registry import get_registry
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_selector(state: AgentState) -> dict:
    registry = get_registry()
    tracker = db.get_tracker()
    ctx = build_collection_context(tracker)
    selection = CollectionStrategyFactory.create(ctx).select(ctx)
    counts = tracker.count_by_label()
    available_sources = registry.list_names()
    source_labels = {name: registry.get(name).expected_label for name in available_sources}

    decision = None
    if ctx.phase == "steady" and ollama_source_selection_enabled():
        decision = choose_sources_with_ollama(
            available_sources=available_sources,
            source_labels=source_labels,
            fallback_source=selection.source_type,
            fallback_label=selection.expected_label,
            counts=counts,
        )
        if decision is not None:
            selected_labels = {registry.get(name).expected_label for name in decision.selected_sources}
            if len(selected_labels) != 1:
                logger.info("Ollama selected mixed-label sources; using strategy fallback")
                decision = None
            elif decision.expected_label != selection.expected_label:
                logger.info(
                    "Ollama selected label=%d while strategy requires label=%d; using strategy",
                    decision.expected_label,
                    selection.expected_label,
                )
                decision = None

    if decision is None:
        source_type = selection.source_type
        selected_sources = selection.selected_sources
        expected_label = selection.expected_label
        discovery_strategy = selection.discovery_strategy
        cti_queries = selection.cti_queries
        collection_phase = selection.collection_phase
        route_hint = selection.route_hint
    else:
        source_type = decision.source_type
        selected_sources = decision.selected_sources
        expected_label = decision.expected_label
        discovery_strategy = decision.discovery_strategy or "ollama"
        cti_queries = decision.cti_queries
        collection_phase = selection.collection_phase
        route_hint = selection.route_hint

    return {
        "source_type": source_type,
        "selected_sources": selected_sources,
        "discovery_strategy": discovery_strategy,
        "collection_phase": collection_phase,
        "route_hint": route_hint,
        "cti_queries": cti_queries,
        "expected_label": expected_label,
        "sample_candidates": [],
        "discovered_hashes": [],
        "downloaded_paths": [],
        "feature_vectors": [],
        "feature_errors": {},
        "predictions": {},
        "section_entropies": [],
        "new_labeled_batch": [],
        "drift_detected": False,
        "hash_metadata": {},
        "rejected_candidates": [],
        "capa_results": {},
        "cti_evidence": {},
        "intel_poll_stats": {},
        "intel_sources_polled": [],
        "bootstrap_metrics": {},
    }

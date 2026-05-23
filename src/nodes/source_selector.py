"""Source selector node — choose malware vs benign provider."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.collection import CollectionStrategyFactory, build_collection_context
from src.config import IMBALANCE_ALERT_RATIO, TARGET_MALWARE_BENIGN_RATIO, ollama_source_selection_enabled
from src.llm import choose_sources_with_ollama
from src.sources.registry import get_registry
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_selector(state: AgentState) -> dict:
    registry = get_registry()
    tracker = db.get_tracker()
    ctx = build_collection_context(tracker)
    selection = CollectionStrategyFactory.create(ctx, tracker=tracker).select(ctx)
    counts = tracker.count_by_label()
    available_sources = registry.list_names()
    source_labels = {name: registry.get(name).expected_label for name in available_sources}

    # Imbalance monitoring
    n_mal = int(counts.get(1, 0))
    n_ben = int(counts.get(0, 0))
    if n_ben > 0 and n_mal > 0:
        ratio = n_mal / n_ben
        if ratio < IMBALANCE_ALERT_RATIO:
            logger.warning(
                "Class imbalance: malware=%d benign=%d ratio=%.2f (target=%.2f)"
                " — too few malware, prioritising malware collection",
                n_mal, n_ben, ratio, TARGET_MALWARE_BENIGN_RATIO,
            )
        elif ratio > (1.0 / IMBALANCE_ALERT_RATIO):
            logger.warning(
                "Class imbalance: malware=%d benign=%d ratio=%.2f (target=%.2f)"
                " — too few benign, prioritising benign collection",
                n_mal, n_ben, ratio, TARGET_MALWARE_BENIGN_RATIO,
            )
    elif n_ben == 0 and n_mal > 0:
        logger.warning("Class imbalance: %d malware, 0 benign — prioritising benign collection", n_mal)
    elif n_mal == 0 and n_ben > 0:
        logger.warning("Class imbalance: 0 malware, %d benign — prioritising malware collection", n_ben)

    decision = None
    if ctx.phase == "steady" and selection.expected_label != -1 and ollama_source_selection_enabled():
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
        collection_phase = selection.collection_phase
        route_hint = selection.route_hint
    else:
        source_type = decision.source_type
        selected_sources = decision.selected_sources
        expected_label = decision.expected_label
        discovery_strategy = decision.discovery_strategy or "ollama"
        collection_phase = selection.collection_phase
        route_hint = selection.route_hint

    return {
        "source_type": source_type,
        "selected_sources": selected_sources,
        "discovery_strategy": discovery_strategy,
        "collection_phase": collection_phase,
        "route_hint": route_hint,
        "expected_label": expected_label,
        "sample_candidates": [],
        "discovered_hashes": [],
        "downloaded_paths": [],
        "feature_vectors": [],
        "feature_errors": {},
        "predictions": {},
        "evaluation_metrics": {},
        "section_entropies": [],
        "new_labeled_batch": [],
        "drift_detected": False,
        "drift_stats": {},
        "drift_pre_metrics": {},
        "pending_drift_log": False,
        "hash_metadata": {},
        "rejected_candidates": [],
        "cti_evidence": {},
        "intel_poll_stats": {},
        "intel_sources_polled": [],
        "bootstrap_metrics": {},
    }

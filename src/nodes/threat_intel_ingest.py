"""Threat intel ingest node — integrated collector replacing ThreatIngestor queue."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.collection.context import build_collection_context
from src.config import (
    INTEL_INGEST_ENABLED,
    INTEL_PENDING_CAP_MULT,
    MIN_TRAIN_MALWARE,
    PE_FETCH_LIMIT,
)
from src.intel.collector import ThreatIntelCollector
from src.state import AgentState
from src.tools.malwarebazaar import reset_mb_run_budget

logger = logging.getLogger(__name__)


def _should_discover(collector: ThreatIntelCollector, state: AgentState) -> bool:
    if collector.sources.count_enabled() == 0:
        return True
    return state.discovery_strategy in ("", "ollama", "intel_discover")


def _should_poll(tracker: db.MalwareTracker) -> bool:
    pending = tracker.fetch_pending_hashes(limit=PE_FETCH_LIMIT * INTEL_PENDING_CAP_MULT + 1)
    return len(pending) < PE_FETCH_LIMIT * INTEL_PENDING_CAP_MULT


def _bootstrap_aggressive(tracker: db.MalwareTracker) -> bool:
    counts = tracker.count_by_label()
    return int(counts.get(1, 0)) < MIN_TRAIN_MALWARE


def threat_intel_ingest(state: AgentState) -> dict:
    """Run discover/poll/validate and load pending candidates into graph state."""
    reset_mb_run_budget()
    if not INTEL_INGEST_ENABLED:
        return {"sample_candidates": []}

    tracker = db.get_tracker()
    if build_collection_context(tracker).phase == "bootstrap":
        logger.info("Threat intel ingest skipped: collection phase is bootstrap")
        return {
            "sample_candidates": [],
            "intel_poll_stats": {"skipped": "bootstrap"},
            "intel_sources_polled": [],
        }

    collector = ThreatIntelCollector(tracker=tracker)
    stats: dict = {}

    stats["seed_sources"] = collector.seed_curated_sources()

    discover = _should_discover(collector, state)
    poll = _should_poll(tracker)

    if discover:
        stats["discover"] = collector.discover_sources(
            max_sources=8,
            extra_queries=state.cti_queries or None,
        )

    raw: list = []
    ti_raw, ti_stats = collector.poll_threatingestor_artifacts()
    stats["threatingestor"] = ti_stats
    raw.extend(ti_raw)

    if poll:
        max_sources = 8 if _bootstrap_aggressive(tracker) else 5
        max_candidates = 80 if _bootstrap_aggressive(tracker) else 50
        native_raw = collector.poll_due_feeds(
            max_sources=max_sources,
            max_candidates=max_candidates,
        )
        stats["native_sources"] = collector.last_native_poll_stats
        native_stats = collector.last_native_poll_stats
        logger.info(
            "Native CTI feeds: sources=%d disabled=%d entries=%d raw_hashes=%d pe_urls=%d returned=%d",
            int(native_stats.get("sources_polled", 0)),
            int(native_stats.get("sources_disabled", 0)),
            int(native_stats.get("entries", 0)),
            int(native_stats.get("raw_hashes", 0)),
            int(native_stats.get("raw_pe_urls", 0)),
            int(native_stats.get("returned", 0)),
        )
        raw.extend(native_raw)

    stats["poll_count"] = len(raw)
    if raw:
        stats["validate"] = collector.validate_and_queue(raw)

    validate_stats = stats.get("validate") or {}
    ti_shas = {str(item.get("sha256", "")).lower() for item in ti_raw if item.get("sha256")}
    ti_queued = ti_shas.intersection(set(validate_stats.get("queued_hashes", [])))
    ti_existing = ti_shas.intersection(set(validate_stats.get("existing_hashes", [])))
    logger.info(
        "ThreatIngestor: seen=%d sha256=%d queued=%d existing=%d rejected=%d ignored_format=%d",
        int(ti_stats.get("seen", 0)),
        int(ti_stats.get("candidates", 0)),
        len(ti_queued),
        len(ti_existing),
        max(0, int(ti_stats.get("candidates", 0)) - len(ti_queued) - len(ti_existing)),
        int(ti_stats.get("ignored_format", 0)),
    )

    candidates = collector.pending_to_candidates(limit=PE_FETCH_LIMIT)
    cti_evidence = dict(state.cti_evidence)
    for item in raw:
        sha = str(item.get("sha256") or "").lower()
        if len(sha) == 64:
            cti_evidence[sha] = {
                "url": item.get("article_url", ""),
                "feed_url": item.get("feed_url", ""),
                "title": item.get("title", ""),
                "intel_source_id": item.get("source_id"),
                "context": (item.get("context") or "")[:500],
            }
            for cand in candidates:
                if cand.get("external_id") == sha:
                    meta = dict(cand.get("metadata") or {})
                    meta["intel_source_id"] = item.get("source_id")
                    meta["source_id"] = item.get("source_id")
                    if item.get("discovery_source") == "intel_threatingestor":
                        meta["discovery_source"] = "intel_threatingestor"
                    cand["metadata"] = meta

    sources_polled = [s.get("url", "") for s in collector.sources.all_sources()[:10]]

    logger.info(
        "Threat intel ingest: candidates=%d stats=%s",
        len(candidates),
        stats,
    )
    return {
        "source_type": "malwarebazaar",
        "expected_label": 1,
        "sample_candidates": candidates,
        "intel_poll_stats": stats,
        "intel_sources_polled": sources_polled,
        "cti_evidence": cti_evidence,
    }

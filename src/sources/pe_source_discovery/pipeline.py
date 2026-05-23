"""Orchestrate PE source discovery: plan → search → fetch → classify → register."""

from __future__ import annotations

import logging
from typing import Any

from src.config import PE_DISCOVERY_MAX_URLS
from src.sources.pe_source_discovery.page_classify import classify_pe_source_page, refine_with_llm
from src.sources.pe_source_discovery.page_fetch import fetch_page_text
from src.sources.pe_source_discovery.planner import plan_discovery_targets
from src.sources.pe_source_discovery.registry_register import register_classification
from src.sources.pe_source_store import PESourceStore

logger = logging.getLogger(__name__)


def run_pe_source_discovery(
    store: PESourceStore | None = None,
    *,
    max_urls: int | None = None,
    need_malware: bool = True,
    need_benign: bool = False,
    use_llm: bool = True,
) -> dict[str, Any]:
    """Discover and register PE data sources (no sample download)."""
    pe_store = store or PESourceStore()
    seeded = pe_store.seed_defaults()
    budget = max_urls or PE_DISCOVERY_MAX_URLS

    stats: dict[str, Any] = {
        "seeded": seeded,
        "searched": 0,
        "fetched": 0,
        "registered": 0,
        "active_count": pe_store.count_active(),
    }

    urls: list[dict[str, str]] = []
    stats["searched"] = len(urls)

    for row in urls:
        url = row["url"]
        text = fetch_page_text(url)
        if not text:
            text = row.get("snippet") or ""
        stats["fetched"] += 1
        heuristic = classify_pe_source_page(url, text)
        classification = (
            refine_with_llm(url, text, heuristic) if use_llm else heuristic
        )
        if register_classification(pe_store, url, classification, discovery_query=row.get("query", "")):
            stats["registered"] += 1
        for link in classification.get("candidate_links") or []:
            if stats["fetched"] >= budget:
                break
            link_text = fetch_page_text(link)
            if not link_text:
                continue
            stats["fetched"] += 1
            sub = classify_pe_source_page(link, link_text)
            if use_llm:
                sub = refine_with_llm(link, link_text, sub)
            if register_classification(pe_store, link, sub, discovery_query=row.get("query", "")):
                stats["registered"] += 1

    stats["active_count"] = pe_store.count_active()
    logger.info("PE source discovery: %s", stats)
    return stats

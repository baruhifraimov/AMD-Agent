"""Provider discovery with bootstrap malware fallback to dynamic_cti."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.collection.context import CollectionContext, build_collection_context
from src.config import PE_FETCH_LIMIT
from src.sources.base import SampleCandidate
from src.sources.registry import SourceRegistry, get_registry

logger = logging.getLogger(__name__)


def _known_bad_or_downloaded(candidate: SampleCandidate, tracker: db.MalwareTracker) -> bool:
    sha = str(candidate.download_ref.get("sha256") or candidate.external_id).lower()
    return len(sha) == 64 and (
        tracker.is_downloaded(sha)
        or tracker.is_corrupted(sha)
        or tracker.is_pending(sha)
    )


def discover_with_fallback(
    source_names: list[str],
    *,
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
    ctx: CollectionContext | None = None,
    expected_label: int = 1,
    limit: int | None = None,
    cti_queries: list[str] | None = None,
) -> list[SampleCandidate]:
    """Discover from primary providers; bootstrap malware may fall back to dynamic_cti."""
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    if ctx is None:
        ctx = build_collection_context(tracker)
    fetch_limit = limit or PE_FETCH_LIMIT
    candidates: list[SampleCandidate] = []

    for source_name in source_names:
        provider = registry.get(source_name)
        try:
            discovered = provider.discover(fetch_limit * 5)
        except Exception as exc:
            logger.warning("Discovery failed for provider=%s: %s", provider.name, exc)
            continue
        fresh = [c for c in discovered if not _known_bad_or_downloaded(c, tracker)]
        candidates.extend(fresh)
        logger.info(
            "Discovered %d/%d fresh candidates from provider=%s label=%d",
            len(fresh),
            len(discovered),
            provider.name,
            provider.expected_label,
        )
        if len(candidates) >= fetch_limit:
            break

    if not candidates and expected_label == 1:
        if "threatfox" in registry.list_names():
            try:
                tf_provider = registry.get("threatfox")
                discovered = tf_provider.discover(fetch_limit * 5)
            except Exception as exc:
                logger.warning("ThreatFox fallback failed: %s", exc)
                discovered = []
            fresh = [c for c in discovered if not _known_bad_or_downloaded(c, tracker)]
            candidates.extend(fresh)
            logger.info(
                "Primary dry (phase=%s); ThreatFox fallback yielded %d fresh",
                ctx.phase,
                len(fresh),
            )

    if not candidates and expected_label == 1 and "twitter" in registry.list_names():
        try:
            tw_provider = registry.get("twitter")
            discovered = tw_provider.discover(fetch_limit * 5)
        except Exception as exc:
            logger.warning("Twitter CTI fallback failed: %s", exc)
            discovered = []
        fresh = [c for c in discovered if not _known_bad_or_downloaded(c, tracker)]
        candidates.extend(fresh)
        logger.info(
            "Twitter CTI fallback (phase=%s) yielded %d fresh candidates",
            ctx.phase,
            len(fresh),
        )

    if not candidates and expected_label == 1:
        logger.info(
            "Primary discovery returned 0 fresh (phase=%s); falling back to dynamic_cti/DDG",
            ctx.phase,
        )
        from src.intel.collector import ThreatIntelCollector

        try:
            discovered = ThreatIntelCollector(tracker=tracker).web_discover(
                fetch_limit * 5,
                queries=cti_queries or None,
            )
        except Exception as exc:
            logger.warning("dynamic_cti fallback failed: %s", exc)
            discovered = []
        fresh = [c for c in discovered if not _known_bad_or_downloaded(c, tracker)]
        candidates.extend(fresh)
        logger.info("dynamic_cti fallback yielded %d fresh candidates", len(fresh))

    return candidates[:fetch_limit]

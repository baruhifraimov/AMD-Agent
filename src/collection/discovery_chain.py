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


def _candidate_key(candidate: SampleCandidate) -> str:
    ref = candidate.download_ref
    for key in ("sha256", "fallback_url", "url"):
        value = str(ref.get(key) or "").strip().lower()
        if value:
            return value
    return str(candidate.external_id).strip().lower()


def _append_fresh_candidates(
    candidates: list[SampleCandidate],
    discovered: list[SampleCandidate],
    *,
    tracker: db.MalwareTracker,
    seen: set[str],
    fetch_limit: int,
) -> tuple[int, int]:
    fresh = 0
    returned = 0
    for candidate in discovered:
        key = _candidate_key(candidate)
        if not key or key in seen:
            continue
        if _known_bad_or_downloaded(candidate, tracker):
            continue
        seen.add(key)
        fresh += 1
        if len(candidates) < fetch_limit:
            candidates.append(candidate)
            returned += 1
    return fresh, returned


def discover_with_fallback(
    source_names: list[str],
    *,
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
    ctx: CollectionContext | None = None,
    expected_label: int = 1,
    limit: int | None = None,
    cti_queries: list[str] | None = None,
    stats: list[dict] | None = None,
) -> list[SampleCandidate]:
    """Discover from providers and keep filling malware batches via fallbacks."""
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    if ctx is None:
        ctx = build_collection_context(tracker)
    fetch_limit = limit or PE_FETCH_LIMIT
    candidates: list[SampleCandidate] = []
    seen: set[str] = set()
    available = set(registry.list_names())
    provider_chain = list(dict.fromkeys(source_names))

    if expected_label == 1:
        for fallback in ("threatfox", "twitter", "dynamic_cti"):
            if fallback in available and fallback not in provider_chain:
                provider_chain.append(fallback)

    for source_name in provider_chain:
        if len(candidates) >= fetch_limit:
            break
        request_limit = max((fetch_limit - len(candidates)) * 5, fetch_limit)
        provider_name = source_name
        try:
            if source_name == "dynamic_cti":
                provider_name = "dynamic_cti"
                from src.intel.collector import ThreatIntelCollector

                discovered = ThreatIntelCollector(tracker=tracker).web_discover(
                    request_limit,
                    queries=cti_queries or None,
                )
            else:
                provider = registry.get(source_name)
                provider_name = provider.name
                discovered = provider.discover(request_limit)
        except Exception as exc:
            logger.warning("Discovery failed for provider=%s: %s", provider_name, exc)
            if stats is not None:
                stats.append(
                    {
                        "stage": "discovery",
                        "provider": provider_name,
                        "discovered": 0,
                        "fresh": 0,
                        "returned": 0,
                        "label": expected_label,
                        "phase": ctx.phase,
                        "error": str(exc),
                    }
                )
            continue
        fresh, returned = _append_fresh_candidates(
            candidates,
            discovered,
            tracker=tracker,
            seen=seen,
            fetch_limit=fetch_limit,
        )
        if stats is not None:
            stats.append(
                {
                    "stage": "discovery",
                    "provider": provider_name,
                    "discovered": len(discovered),
                    "fresh": fresh,
                    "returned": returned,
                    "label": expected_label,
                    "phase": ctx.phase,
                }
            )
        logger.info(
            "Discovered %d/%d fresh candidates from provider=%s label=%d returned=%d/%d",
            fresh,
            len(discovered),
            provider_name,
            expected_label,
            returned,
            fetch_limit,
        )

    return candidates[:fetch_limit]

"""Provider discovery with bootstrap malware fallback chain."""

from __future__ import annotations

import src.db.tracker as db
from src.collection.context import CollectionContext, build_collection_context
from src.config import BENIGN_PROVIDER_NAMES, MALWARE_FALLBACK_PROVIDERS, PE_FETCH_LIMIT, malshare_enabled
from src.collection.provider_stats import summarize_discovery_providers
from src.log import PHASE_DISCOVERY, get_logger, phase_log, vlog
from src.tools.malwarebazaar_api import reset_mb_run_budget
from src.sources.base import SampleCandidate
from src.sources.registry import SourceRegistry, get_registry

logger = get_logger(__name__)


def _known_bad_or_downloaded(candidate: SampleCandidate, tracker: db.MalwareTracker) -> bool:
    sha = str(candidate.download_ref.get("sha256") or candidate.external_id).lower()
    return len(sha) == 64 and (
        tracker.is_downloaded(sha)
        or tracker.is_corrupted(sha)
        or tracker.is_pending(sha)
    )


def _candidate_key(candidate: SampleCandidate) -> str:
    ref = candidate.download_ref
    for key in ("sha256", "fallback_url", "url", "path"):
        value = str(ref.get(key) or "").strip().lower()
        if value:
            return value
    return str(candidate.external_id).strip().lower()


def _candidate_source_url(candidate: SampleCandidate) -> str:
    return str(
        candidate.download_ref.get("url")
        or candidate.download_ref.get("fallback_url")
        or candidate.download_ref.get("path")
        or candidate.metadata.get("source_url")
        or ""
    ).strip()


def _candidate_db_key(candidate: SampleCandidate) -> str:
    return f"{candidate.provider}:{_candidate_key(candidate)}"


def _record_candidate_seen(
    tracker: db.MalwareTracker,
    candidate: SampleCandidate,
    *,
    status: str,
) -> None:
    key = _candidate_db_key(candidate)
    if not key:
        return
    candidate.metadata["candidate_key"] = key
    sha = str(candidate.download_ref.get("sha256") or "").lower()
    tracker.record_candidate_seen(
        candidate_key=key,
        provider=candidate.provider,
        label=candidate.expected_label,
        external_id=str(candidate.external_id),
        sha256=sha if len(sha) == 64 else "",
        source_url=_candidate_source_url(candidate),
        status=status,
    )


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
        _record_candidate_seen(tracker, candidate, status="seen")
        key = _candidate_key(candidate)
        if not key or key in seen:
            tracker.record_candidate_outcome(_candidate_db_key(candidate), status="duplicate")
            continue
        if _known_bad_or_downloaded(candidate, tracker):
            tracker.record_candidate_outcome(_candidate_db_key(candidate), status="duplicate")
            continue
        seen.add(key)
        fresh += 1
        if len(candidates) < fetch_limit:
            candidates.append(candidate)
            tracker.record_candidate_outcome(_candidate_db_key(candidate), status="returned")
            returned += 1
    return fresh, returned


def _discover_source_candidates(
    source_name: str,
    *,
    request_limit: int,
    registry: SourceRegistry,
    tracker: db.MalwareTracker,
) -> tuple[str, list[SampleCandidate]]:
    provider = registry.get(source_name)
    return provider.name, provider.discover(request_limit)


def discover_active_malware_sources(
    source_names: list[str] | None = None,
    *,
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
    ctx: CollectionContext | None = None,
    limit: int | None = None,
    stats: list[dict] | None = None,
    existing_candidates: list[SampleCandidate] | None = None,
) -> list[SampleCandidate]:
    """Discover malware while reserving slots for enabled first-class APIs."""
    reset_mb_run_budget()
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    if ctx is None:
        ctx = build_collection_context(tracker)
    fetch_limit = limit or PE_FETCH_LIMIT
    requested_sources = list(dict.fromkeys(source_names or ["malwarebazaar"]))
    available = set(registry.list_names())

    if not malshare_enabled() or "malshare" not in available:
        return discover_with_fallback(
            requested_sources,
            registry=registry,
            tracker=tracker,
            ctx=ctx,
            expected_label=1,
            limit=fetch_limit,

            stats=stats,
        )

    active_sources = ["malwarebazaar", "malshare"]
    candidates: list[SampleCandidate] = []
    seen = {
        _candidate_key(candidate)
        for candidate in (existing_candidates or [])
        if _candidate_key(candidate)
    }
    slots = {
        "malwarebazaar": (fetch_limit + 1) // 2,
        "malshare": fetch_limit // 2,
    }

    for source_name in active_sources:
        slot = slots[source_name]
        if slot <= 0:
            continue
        provider_name = source_name
        request_limit = max(slot * 5, 1)
        try:
            provider_name, discovered = _discover_source_candidates(
                source_name,
                request_limit=request_limit,
                registry=registry,
                tracker=tracker,
    
            )
        except Exception as exc:
            logger.warning("[%s] Discovery failed for provider=%s: %s", PHASE_DISCOVERY, provider_name, exc)
            if stats is not None:
                stats.append(
                    {
                        "stage": "active_malware_fill",
                        "provider": provider_name,
                        "requested": request_limit,
                        "discovered": 0,
                        "fresh": 0,
                        "returned": 0,
                        "label": 1,
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
            fetch_limit=len(candidates) + slot,
        )
        if stats is not None:
            stats.append(
                {
                    "stage": "active_malware_fill",
                    "provider": provider_name,
                    "requested": request_limit,
                    "discovered": len(discovered),
                    "fresh": fresh,
                    "returned": returned,
                    "label": 1,
                    "phase": ctx.phase,
                }
            )

    if len(candidates) < fetch_limit:
        topup_stats: list[dict] = []
        topup_sources = list(dict.fromkeys([*active_sources, *requested_sources]))
        topup = discover_with_fallback(
            topup_sources,
            registry=registry,
            tracker=tracker,
            ctx=ctx,
            expected_label=1,
            limit=fetch_limit - len(candidates),

            stats=topup_stats,
        )
        _append_fresh_candidates(
            candidates,
            topup,
            tracker=tracker,
            seen=seen,
            fetch_limit=fetch_limit,
        )
        if stats is not None:
            for item in topup_stats:
                topup_item = dict(item)
                topup_item["stage"] = "active_malware_topup"
                stats.append(topup_item)

    return candidates[:fetch_limit]


def _source_slots(source_names: list[str], fetch_limit: int) -> dict[str, int]:
    if not source_names:
        return {}
    base = fetch_limit // len(source_names)
    extra = fetch_limit % len(source_names)
    return {
        name: base + (1 if idx < extra else 0)
        for idx, name in enumerate(source_names)
    }


def discover_active_benign_sources(
    source_names: list[str],
    *,
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
    ctx: CollectionContext | None = None,
    limit: int | None = None,
    stats: list[dict] | None = None,
) -> list[SampleCandidate]:
    """Discover benign samples across all selected benign providers."""
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    if ctx is None:
        ctx = build_collection_context(tracker)
    fetch_limit = limit or PE_FETCH_LIMIT
    available = set(registry.list_names())
    active_sources = [
        name
        for name in list(dict.fromkeys(source_names))
        if name in available and name in BENIGN_PROVIDER_NAMES
    ]
    if not active_sources:
        return []
    if len(active_sources) == 1:
        return discover_with_fallback(
            active_sources,
            registry=registry,
            tracker=tracker,
            ctx=ctx,
            expected_label=0,
            limit=fetch_limit,
            stats=stats,
        )

    candidates: list[SampleCandidate] = []
    seen: set[str] = set()
    slots = _source_slots(active_sources, fetch_limit)
    for source_name in active_sources:
        slot = slots[source_name]
        if slot <= 0:
            continue
        provider_name = source_name
        request_limit = max(slot * 5, 1)
        try:
            provider_name, discovered = _discover_source_candidates(
                source_name,
                request_limit=request_limit,
                registry=registry,
                tracker=tracker,
            )
        except Exception as exc:
            logger.warning("[%s] Discovery failed for provider=%s: %s", PHASE_DISCOVERY, provider_name, exc)
            if stats is not None:
                stats.append(
                    {
                        "stage": "active_benign_fill",
                        "provider": provider_name,
                        "requested": request_limit,
                        "discovered": 0,
                        "fresh": 0,
                        "returned": 0,
                        "label": 0,
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
            fetch_limit=len(candidates) + slot,
        )
        if stats is not None:
            stats.append(
                {
                    "stage": "active_benign_fill",
                    "provider": provider_name,
                    "requested": request_limit,
                    "discovered": len(discovered),
                    "fresh": fresh,
                    "returned": returned,
                    "label": 0,
                    "phase": ctx.phase,
                }
            )

    if len(candidates) < fetch_limit:
        topup_stats: list[dict] = []
        topup = discover_with_fallback(
            active_sources,
            registry=registry,
            tracker=tracker,
            ctx=ctx,
            expected_label=0,
            limit=fetch_limit - len(candidates),
            stats=topup_stats,
        )
        _append_fresh_candidates(
            candidates,
            topup,
            tracker=tracker,
            seen=seen,
            fetch_limit=fetch_limit,
        )
        if stats is not None:
            for item in topup_stats:
                topup_item = dict(item)
                topup_item["stage"] = "active_benign_topup"
                stats.append(topup_item)

    return candidates[:fetch_limit]


def discover_mixed_sources(
    source_names: list[str],
    *,
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
    ctx: CollectionContext | None = None,
    limit: int | None = None,
    stats: list[dict] | None = None,
) -> list[SampleCandidate]:
    """Discover an interleaved malware/benign batch for temporal split health."""
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    if ctx is None:
        ctx = build_collection_context(tracker)
    fetch_limit = limit or PE_FETCH_LIMIT
    benign_sources = [
        name
        for name in list(dict.fromkeys(source_names))
        if name in BENIGN_PROVIDER_NAMES and name in set(registry.list_names())
    ]
    if not benign_sources:
        benign_sources = [name for name in BENIGN_PROVIDER_NAMES if name in set(registry.list_names())]

    malware_limit = (fetch_limit + 1) // 2
    benign_limit = fetch_limit // 2
    malware_stats: list[dict] = []
    benign_stats: list[dict] = []
    malware = discover_active_malware_sources(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        limit=malware_limit,
        stats=malware_stats,
    )
    benign = discover_active_benign_sources(
        benign_sources,
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        limit=benign_limit,
        stats=benign_stats,
    )
    if stats is not None:
        for item in [*malware_stats, *benign_stats]:
            mixed = dict(item)
            mixed["mixed"] = 1
            stats.append(mixed)

    out: list[SampleCandidate] = []
    for idx in range(max(len(malware), len(benign))):
        if idx < len(malware):
            out.append(malware[idx])
        if idx < len(benign):
            out.append(benign[idx])
        if len(out) >= fetch_limit:
            break
    return out[:fetch_limit]


def discover_with_fallback(
    source_names: list[str],
    *,
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
    ctx: CollectionContext | None = None,
    expected_label: int = 1,
    limit: int | None = None,
    stats: list[dict] | None = None,
) -> list[SampleCandidate]:
    """Discover from providers and keep filling malware batches via fallbacks."""
    reset_mb_run_budget()
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    if ctx is None:
        ctx = build_collection_context(tracker)
    fetch_limit = limit or PE_FETCH_LIMIT
    candidates: list[SampleCandidate] = []
    seen: set[str] = set()
    available = set(registry.list_names())
    provider_chain = list(dict.fromkeys(source_names))
    primary_sources = set(provider_chain)

    if expected_label == 1:
        for fallback in MALWARE_FALLBACK_PROVIDERS:
            if fallback in available and fallback not in provider_chain:
                provider_chain.append(fallback)

    for source_name in provider_chain:
        if len(candidates) >= fetch_limit:
            break
        remaining = fetch_limit - len(candidates)
        request_limit = fetch_limit * 5 if source_name in primary_sources else remaining
        request_limit = max(request_limit, 1)
        provider_name = source_name
        try:
            provider_name, discovered = _discover_source_candidates(
                source_name,
                request_limit=request_limit,
                registry=registry,
                tracker=tracker,
    
            )
        except Exception as exc:
            logger.warning("[%s] Discovery failed for provider=%s: %s", PHASE_DISCOVERY, provider_name, exc)
            if stats is not None:
                stats.append(
                    {
                        "stage": "discovery",
                        "provider": provider_name,
                        "requested": request_limit,
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
                    "requested": request_limit,
                    "discovered": len(discovered),
                    "fresh": fresh,
                    "returned": returned,
                    "label": expected_label,
                    "phase": ctx.phase,
                }
            )
        vlog(
            logger,
            "info",
            "Discovered %d/%d fresh candidates from provider=%s label=%d returned=%d/%d",
            fresh,
            len(discovered),
            provider_name,
            expected_label,
            returned,
            fetch_limit,
        )

    phase_log(
        logger,
        PHASE_DISCOVERY,
        "Fallback chain done: %d/%d candidates (label=%d) via %s",
        len(candidates),
        fetch_limit,
        expected_label,
        summarize_discovery_providers(stats or []),
    )
    return candidates[:fetch_limit]

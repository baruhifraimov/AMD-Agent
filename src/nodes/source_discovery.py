"""Source discovery node — delegate to active PE provider."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.config import PE_FETCH_LIMIT
from src.sources.base import SampleCandidate
from src.sources.registry import get_registry
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_discovery(state: AgentState) -> dict:
    registry = get_registry()
    tracker = db.get_tracker()
    source_names = state.selected_sources or ([state.source_type] if state.source_type else [])
    candidates: list[SampleCandidate] = []
    for source_name in source_names:
        provider = registry.get(source_name)
        try:
            discovered = provider.discover(PE_FETCH_LIMIT * 5)
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
        if len(candidates) >= PE_FETCH_LIMIT:
            break
    candidates = candidates[:PE_FETCH_LIMIT]
    return {
        "sample_candidates": [c.to_dict() for c in candidates],
        "expected_label": state.expected_label,
    }


def _known_bad_or_downloaded(candidate: SampleCandidate, tracker: db.MalwareTracker) -> bool:
    sha = str(candidate.download_ref.get("sha256") or candidate.external_id).lower()
    return len(sha) == 64 and (tracker.is_downloaded(sha) or tracker.is_corrupted(sha))

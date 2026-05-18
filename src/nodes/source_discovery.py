"""Source discovery node — delegate to active PE provider."""

from __future__ import annotations

import logging

from src.config import PE_FETCH_LIMIT
from src.sources.base import SampleCandidate
from src.sources.registry import get_registry
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_discovery(state: AgentState) -> dict:
    registry = get_registry()
    provider = registry.get(state.source_type)
    candidates = provider.discover(PE_FETCH_LIMIT)
    logger.info(
        "Discovered %d candidates from provider=%s label=%d",
        len(candidates),
        provider.name,
        provider.expected_label,
    )
    return {
        "sample_candidates": [c.to_dict() for c in candidates],
        "expected_label": provider.expected_label,
    }

"""Dataset-aware provider selection for malware vs benign balance."""

from __future__ import annotations

import src.db.tracker as db
from src.collection.balance import choose_benign_provider, next_label
from src.collection.context import build_collection_context
from src.collection.factory import CollectionStrategyFactory
from src.log import PHASE_SELECT, get_logger, phase_log
from src.sources.base import PESourceProvider
from src.sources.registry import SourceRegistry, get_registry

logger = get_logger(__name__)


def choose_provider(
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
) -> PESourceProvider:
    """Pick provider via bootstrap/steady collection strategies."""
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    ctx = build_collection_context(tracker)
    selection = CollectionStrategyFactory.create(ctx).select(ctx)
    if selection.expected_label == -1:
        provider = choose_benign_provider(registry, tracker)
    else:
        provider = registry.get(selection.source_type)
    counts = tracker.count_by_label()
    phase_log(
        logger,
        PHASE_SELECT,
        "Provider=%s phase=%s malware=%d benign=%d",
        provider.name,
        selection.collection_phase,
        counts.get(1, 0),
        counts.get(0, 0),
    )
    return provider


_next_label = next_label
_choose_benign_provider = choose_benign_provider

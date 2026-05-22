"""Steady-state source selection (intel queue or dynamic CTI)."""

from __future__ import annotations

from src.collection.context import CollectionContext
from src.collection.strategies.base import SourceSelectionResult
from src.collection.balance import choose_benign_sources, next_label
from src.sources.registry import get_registry


class SteadyStateSelectionStrategy:
    def select(self, ctx: CollectionContext) -> SourceSelectionResult:
        registry = get_registry()
        if next_label(ctx.malware_count, ctx.benign_count) == 0:
            selected_sources = choose_benign_sources(registry)
            provider = registry.get(selected_sources[0])
            return SourceSelectionResult(
                source_type=provider.name,
                selected_sources=selected_sources,
                expected_label=0,
                discovery_strategy="steady_benign_balance",
                collection_phase="steady",
            )
        discovery_strategy = (
            "intel_pending_queue" if ctx.pending_depth > 0 else "steady_intel_poll"
        )
        return SourceSelectionResult(
            source_type="malwarebazaar",
            selected_sources=["malwarebazaar"],
            expected_label=1,
            discovery_strategy=discovery_strategy,
            collection_phase="steady",
            route_hint="threat_intel_ingest",
        )

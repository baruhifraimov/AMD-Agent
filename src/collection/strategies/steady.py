"""Steady-state source selection."""

from __future__ import annotations

import src.db.tracker as db
from src.collection.context import CollectionContext
from src.collection.strategies.base import SourceSelectionResult
from src.collection.balance import choose_benign_sources, next_label
from src.config import STEADY_BENIGN_EVERY_N, TESSERACT_MIXED_UNTIL_HEALTHY
from src.sources.registry import SourceRegistry, get_registry


class SteadyStateSelectionStrategy:
    def __init__(self, tracker: db.MalwareTracker | None = None) -> None:
        self.tracker = tracker

    def select(self, ctx: CollectionContext) -> SourceSelectionResult:
        registry = get_registry()
        if self.tracker is not None and TESSERACT_MIXED_UNTIL_HEALTHY:
            health = self.tracker.temporal_split_health()
            if not bool(health.get("healthy")):
                return self._mixed(registry, "steady_temporal_mixed")

        if next_label(ctx.malware_count, ctx.benign_count) == 0:
            return self._benign(registry, "steady_benign_balance")

        if self.tracker is not None:
            run_count = self.tracker.increment_collection_counter("steady_selection")
            if run_count % STEADY_BENIGN_EVERY_N == 0:
                return self._benign(registry, "steady_benign_refresh")

        return SourceSelectionResult(
            source_type="malwarebazaar",
            selected_sources=["malwarebazaar"],
            expected_label=1,
            discovery_strategy="steady_malware_active",
            collection_phase="steady",
            route_hint="source_discovery",
        )

    def _benign(self, registry: SourceRegistry, strategy: str) -> SourceSelectionResult:
        selected_sources = choose_benign_sources(registry, self.tracker)
        provider = registry.get(selected_sources[0])
        return SourceSelectionResult(
            source_type=provider.name,
            selected_sources=selected_sources,
            expected_label=0,
            discovery_strategy=strategy,
            collection_phase="steady",
            route_hint="source_discovery",
        )

    def _mixed(self, registry: SourceRegistry, strategy: str) -> SourceSelectionResult:
        selected_sources = ["malwarebazaar", *choose_benign_sources(registry, self.tracker)]
        return SourceSelectionResult(
            source_type="mixed",
            selected_sources=selected_sources,
            expected_label=-1,
            discovery_strategy=strategy,
            collection_phase="steady",
            route_hint="source_discovery",
        )

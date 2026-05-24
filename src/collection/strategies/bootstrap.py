"""Bootstrap-phase source selection (fast path, no threat intel queue)."""

from __future__ import annotations

from src.collection.context import CollectionContext
from src.collection.malware_sources import bootstrap_malware_sources
from src.collection.strategies.base import SourceSelectionResult
from src.config import MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE
import src.db.tracker as db
from src.collection.balance import choose_benign_sources
from src.sources.registry import get_registry


class BootstrapSelectionStrategy:
    def __init__(self, tracker: db.MalwareTracker | None = None) -> None:
        self.tracker = tracker

    def select(self, ctx: CollectionContext) -> SourceSelectionResult:
        registry = get_registry()
        malware_deficit = max(0, MIN_TRAIN_MALWARE - ctx.malware_count)
        benign_deficit = max(0, MIN_TRAIN_BENIGN - ctx.benign_count)
        malware_sources = bootstrap_malware_sources(registry)

        if malware_deficit > 0 and benign_deficit > 0:
            selected_sources = [*malware_sources, *choose_benign_sources(registry, self.tracker)]
            return SourceSelectionResult(
                source_type="mixed",
                selected_sources=selected_sources,
                expected_label=-1,
                discovery_strategy="bootstrap_mixed_balance",
                collection_phase="bootstrap",
                route_hint="source_discovery",
            )

        if malware_deficit >= benign_deficit and malware_deficit > 0:
            provider = registry.get(malware_sources[0])
            return SourceSelectionResult(
                source_type=provider.name,
                selected_sources=malware_sources,
                expected_label=1,
                discovery_strategy="bootstrap_fast_path",
                collection_phase="bootstrap",
                route_hint="source_discovery",
            )

        if benign_deficit > 0:
            selected_sources = choose_benign_sources(registry, self.tracker)
            provider = registry.get(selected_sources[0])
            return SourceSelectionResult(
                source_type=provider.name,
                selected_sources=selected_sources,
                expected_label=0,
                discovery_strategy="bootstrap_fast_path",
                collection_phase="bootstrap",
                route_hint="source_discovery",
            )

        provider = registry.get(malware_sources[0])
        return SourceSelectionResult(
            source_type=provider.name,
            selected_sources=malware_sources,
            expected_label=1,
            discovery_strategy="bootstrap_fast_path",
            collection_phase="bootstrap",
            route_hint="source_discovery",
        )

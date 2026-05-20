"""Bootstrap-phase source selection (fast path, no threat intel queue)."""

from __future__ import annotations

from src.collection.context import CollectionContext
from src.collection.strategies.base import SourceSelectionResult
from src.config import MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE
from src.collection.balance import choose_benign_provider
from src.sources.registry import get_registry


class BootstrapSelectionStrategy:
    def select(self, ctx: CollectionContext) -> SourceSelectionResult:
        registry = get_registry()
        malware_deficit = max(0, MIN_TRAIN_MALWARE - ctx.malware_count)
        benign_deficit = max(0, MIN_TRAIN_BENIGN - ctx.benign_count)

        if malware_deficit >= benign_deficit and malware_deficit > 0:
            provider = registry.get("malwarebazaar")
            return SourceSelectionResult(
                source_type=provider.name,
                selected_sources=[provider.name],
                expected_label=1,
                discovery_strategy="bootstrap_fast_path",
                collection_phase="bootstrap",
                route_hint="source_discovery",
            )

        if benign_deficit > 0:
            provider = choose_benign_provider(registry)
            return SourceSelectionResult(
                source_type=provider.name,
                selected_sources=[provider.name],
                expected_label=0,
                discovery_strategy="bootstrap_fast_path",
                collection_phase="bootstrap",
                route_hint="source_discovery",
            )

        provider = registry.get("malwarebazaar")
        return SourceSelectionResult(
            source_type=provider.name,
            selected_sources=[provider.name],
            expected_label=1,
            discovery_strategy="bootstrap_fast_path",
            collection_phase="bootstrap",
            route_hint="source_discovery",
        )

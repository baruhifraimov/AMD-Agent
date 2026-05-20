"""Factory for bootstrap vs steady collection strategies."""

from __future__ import annotations

from src.collection.context import CollectionContext
from src.collection.strategies.base import SourceSelectionStrategy
from src.collection.strategies.bootstrap import BootstrapSelectionStrategy
from src.collection.strategies.steady import SteadyStateSelectionStrategy


class CollectionStrategyFactory:
    @staticmethod
    def create(ctx: CollectionContext) -> SourceSelectionStrategy:
        if ctx.phase == "bootstrap":
            return BootstrapSelectionStrategy()
        return SteadyStateSelectionStrategy()

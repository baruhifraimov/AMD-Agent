"""Factory for bootstrap vs steady collection strategies."""

from __future__ import annotations

import src.db.tracker as db
from src.collection.context import CollectionContext
from src.collection.strategies.base import SourceSelectionStrategy
from src.collection.strategies.bootstrap import BootstrapSelectionStrategy
from src.collection.strategies.steady import SteadyStateSelectionStrategy


class CollectionStrategyFactory:
    @staticmethod
    def create(
        ctx: CollectionContext,
        tracker: db.MalwareTracker | None = None,
    ) -> SourceSelectionStrategy:
        if ctx.phase == "bootstrap":
            return BootstrapSelectionStrategy(tracker=tracker)
        return SteadyStateSelectionStrategy(tracker=tracker)

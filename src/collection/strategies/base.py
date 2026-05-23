"""Source selection strategy contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from src.collection.context import CollectionContext


@dataclass
class SourceSelectionResult:
    source_type: str
    selected_sources: list[str]
    expected_label: int
    discovery_strategy: str
    collection_phase: str
    route_hint: str = ""


class SourceSelectionStrategy(Protocol):
    def select(self, ctx: CollectionContext) -> SourceSelectionResult: ...

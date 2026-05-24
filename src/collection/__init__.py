"""Collection phase strategies and discovery."""

from src.collection.context import (
    CollectionContext,
    build_collection_context,
    current_collection_phase,
)
from src.collection.discovery_chain import (
    discover_active_benign_sources,
    discover_active_malware_sources,
    discover_mixed_sources,
    discover_with_fallback,
)
from src.collection.factory import CollectionStrategyFactory
from src.collection.malware_sources import bootstrap_malware_sources

__all__ = [
    "bootstrap_malware_sources",
    "CollectionContext",
    "CollectionStrategyFactory",
    "build_collection_context",
    "current_collection_phase",
    "discover_active_benign_sources",
    "discover_active_malware_sources",
    "discover_mixed_sources",
    "discover_with_fallback",
]

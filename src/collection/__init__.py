"""Collection phase strategies and discovery (lazy exports to avoid import cycles)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "bootstrap_malware_sources": ("src.collection.malware_sources", "bootstrap_malware_sources"),
    "CollectionContext": ("src.collection.context", "CollectionContext"),
    "build_collection_context": ("src.collection.context", "build_collection_context"),
    "current_collection_phase": ("src.collection.context", "current_collection_phase"),
    "CollectionStrategyFactory": ("src.collection.factory", "CollectionStrategyFactory"),
    "discover_active_benign_sources": (
        "src.collection.discovery_chain",
        "discover_active_benign_sources",
    ),
    "discover_active_malware_sources": (
        "src.collection.discovery_chain",
        "discover_active_malware_sources",
    ),
    "discover_mixed_sources": ("src.collection.discovery_chain", "discover_mixed_sources"),
    "discover_with_fallback": ("src.collection.discovery_chain", "discover_with_fallback"),
}


def __getattr__(name: str) -> Any:
    if name not in _LAZY_IMPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_path, attr = _LAZY_IMPORTS[name]
    import importlib

    module = importlib.import_module(module_path)
    value = getattr(module, attr)
    globals()[name] = value
    return value


if TYPE_CHECKING:
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

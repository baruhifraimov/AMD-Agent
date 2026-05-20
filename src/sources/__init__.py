"""Modular PE sample source providers."""

from src.sources.base import PESourceProvider, SampleCandidate
from src.sources.selector import choose_provider


def get_registry():
    from src.sources.registry import get_registry as _get_registry

    return _get_registry()


def __getattr__(name: str):
    if name == "SourceRegistry":
        from src.sources.registry import SourceRegistry

        return SourceRegistry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "PESourceProvider",
    "SampleCandidate",
    "SourceRegistry",
    "get_registry",
    "choose_provider",
]

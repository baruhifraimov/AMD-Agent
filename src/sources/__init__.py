"""Modular PE sample source providers."""

from src.sources.base import PESourceProvider, SampleCandidate
from src.sources.registry import SourceRegistry, get_registry
from src.sources.selector import choose_provider

__all__ = [
    "PESourceProvider",
    "SampleCandidate",
    "SourceRegistry",
    "get_registry",
    "choose_provider",
]

"""Registry of PE source providers."""

from __future__ import annotations

from src.sources.base import PESourceProvider
from src.sources.dynamic_cti import DynamicCTIProvider
from src.sources.github_releases import GitHubReleasesProvider
from src.sources.malwarebazaar import MalwareBazaarProvider
from src.sources.sysinternals import SysinternalsProvider


class SourceRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, PESourceProvider] = {}

    def register(self, provider: PESourceProvider) -> None:
        self._providers[provider.name] = provider

    def get(self, name: str) -> PESourceProvider:
        if name not in self._providers:
            raise KeyError(f"Unknown PE source provider: {name}")
        return self._providers[name]

    def list_names(self) -> list[str]:
        return sorted(self._providers.keys())

    def all_providers(self) -> list[PESourceProvider]:
        return list(self._providers.values())


def build_default_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register(MalwareBazaarProvider())
    registry.register(DynamicCTIProvider())
    registry.register(SysinternalsProvider())
    registry.register(GitHubReleasesProvider())
    return registry


_default_registry: SourceRegistry | None = None


def get_registry() -> SourceRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = build_default_registry()
    return _default_registry

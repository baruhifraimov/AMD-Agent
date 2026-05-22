"""Registry of PE source providers."""

from __future__ import annotations

from src.sources.base import PESourceProvider


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
    """Register providers lazily to avoid circular imports with src.intel.collector."""
    from src.sources.benign_net import BenignNetProvider
    from src.sources.dynamic_cti import DynamicCTIProvider
    from src.sources.github_releases import GitHubReleasesProvider
    from src.sources.malshare import MalShareProvider
    from src.sources.malwarebazaar import MalwareBazaarProvider
    from src.sources.sysinternals import SysinternalsProvider
    from src.sources.threatfox import ThreatFoxProvider
    from src.sources.twitter import TwitterProvider

    registry = SourceRegistry()
    registry.register(MalwareBazaarProvider())
    registry.register(MalShareProvider())
    registry.register(ThreatFoxProvider())
    registry.register(TwitterProvider())
    registry.register(DynamicCTIProvider())
    registry.register(SysinternalsProvider())
    registry.register(GitHubReleasesProvider())
    registry.register(BenignNetProvider())
    return registry


_default_registry: SourceRegistry | None = None


def get_registry() -> SourceRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = build_default_registry()
    return _default_registry

"""Tests for dataset-aware source selection."""

from src.config import FEATURE_NAMES
from src.sources.registry import SourceRegistry
from src.sources.selector import choose_provider
from src.sources.malwarebazaar import MalwareBazaarProvider
from src.sources.sysinternals import SysinternalsProvider
from src.sources.github_releases import GitHubReleasesProvider


def _registry():
    reg = SourceRegistry()
    reg.register(MalwareBazaarProvider())
    reg.register(SysinternalsProvider())
    reg.register(GitHubReleasesProvider())
    return reg


def _features(seed: int) -> dict[str, float]:
    return {name: float(seed) for name in FEATURE_NAMES}


def test_choose_benign_when_no_benign_samples(tmp_paths):
    tracker = tmp_paths["tracker"]
    provider = choose_provider(_registry(), tracker)
    assert provider.expected_label == 0


def test_choose_malware_when_balanced(tmp_paths):
    tracker = tmp_paths["tracker"]
    for i in range(100):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            "2024-01-01",
            features=_features(i),
            label=0,
        )
    for i in range(100, 200):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            "2024-01-01",
            features=_features(i),
            label=1,
        )
    provider = choose_provider(_registry(), tracker)
    assert provider.name == "malwarebazaar"

"""Tests for GroundTruthResolver."""

from src.config import FEATURE_NAMES
from src.ml.services.ground_truth import GroundTruthResolver


def _features(seed: int) -> dict:
    return {name: float(seed) for name in FEATURE_NAMES}


def test_resolver_prefers_db_label(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "a" * 64
    tracker.insert_sample(
        sha,
        "/tmp/x.bin",
        "2024-01-01",
        features=_features(1),
        label=0,
    )
    resolver = GroundTruthResolver(tracker)
    label = resolver.resolve_label(sha, {"expected_label": 1})
    assert label == 0


def test_resolver_accepts_verified_metadata(tmp_paths):
    resolver = GroundTruthResolver(tmp_paths["tracker"])
    sha = "b" * 64
    label = resolver.resolve_label(
        sha,
        {
            "source_provider": "malwarebazaar",
            "expected_label": 1,
        },
    )
    assert label == 1


def test_resolver_returns_none_without_proof(tmp_paths):
    resolver = GroundTruthResolver(tmp_paths["tracker"])
    sha = "c" * 64
    assert resolver.resolve_label(sha, {}) is None
    assert resolver.resolve_label(sha, {"expected_label": 1}) is None


def test_resolver_accepts_threatfox_metadata(tmp_paths):
    resolver = GroundTruthResolver(tmp_paths["tracker"])
    sha = "d" * 64
    label = resolver.resolve_label(
        sha,
        {"source_provider": "threatfox", "expected_label": 1},
    )
    assert label == 1


def test_resolver_accepts_twitter_metadata(tmp_paths):
    resolver = GroundTruthResolver(tmp_paths["tracker"])
    sha = "e" * 64
    label = resolver.resolve_label(
        sha,
        {"discovery_source": "twitter_cti", "expected_label": 1},
    )
    assert label == 1

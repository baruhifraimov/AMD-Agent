"""Tests for discovery chain pending-hash deduplication."""

from unittest.mock import MagicMock

from src.collection.discovery_chain import discover_with_fallback
from src.collection.context import CollectionContext
from src.sources.base import SampleCandidate


def _make_registry(mb_discover):
    mb = MagicMock()
    mb.name = "malwarebazaar"
    mb.expected_label = 1
    mb.discover.side_effect = mb_discover

    registry = MagicMock()
    registry.list_names.return_value = ["malwarebazaar"]
    registry.get.return_value = mb
    return registry


def test_pending_hash_excluded_from_discovery():
    sha = "a" * 64
    registry = _make_registry(
        lambda _limit: [
            SampleCandidate(sha, "malwarebazaar", 1, {"sha256": sha}),
        ]
    )
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = True

    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=1)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert out == []


def test_duplicate_hash_excluded_within_same_discovery_pass():
    sha = "b" * 64
    registry = _make_registry(
        lambda _limit: [
            SampleCandidate(sha, "malwarebazaar", 1, {"sha256": sha}),
            SampleCandidate(sha, "malwarebazaar", 1, {"sha256": sha}),
        ]
    )
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert len(out) == 1

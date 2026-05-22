"""Tests for ThreatIntelCollector validation and queueing."""

from unittest.mock import MagicMock, patch

import pytest

from src.intel.collector import ThreatIntelCollector


@pytest.fixture
def steady_collector(tmp_paths):
    """Collector with collection phase forced to steady (validate_and_queue active)."""
    with patch("src.collection.context.build_collection_context") as mock_build:
        ctx = MagicMock()
        ctx.phase = "steady"
        mock_build.return_value = ctx
        yield ThreatIntelCollector(tracker=tmp_paths["tracker"])


def test_validate_rejects_invalid_sha(steady_collector):
    collector = steady_collector
    stats = collector.validate_and_queue(
        [{"sha256": "not-a-hash", "source_id": 1}],
        use_semantic_filter=False,
    )
    assert stats["ignored"] == 1
    assert stats["invalid_format"] == 1
    assert stats["queued"] == 0


@patch("src.intel.collector.mb.is_pe_hash", return_value=True)
def test_validate_queues_pe_hash(mock_pe, steady_collector):
    collector = steady_collector
    sha = "a" * 64
    stats = collector.validate_and_queue(
        [{"sha256": sha, "source_id": 1, "context": "malware trojan PE"}],
        use_semantic_filter=False,
    )
    assert stats["queued"] == 1
    pending = collector.tracker.fetch_pending_hashes()
    assert pending[0]["sha256"] == sha


@patch("src.intel.collector.THREATINGESTOR_ENABLED", True)
@patch("src.intel.collector.poll_threatingestor_artifacts")
def test_poll_threatingestor_delegates(mock_poll, tmp_paths):
    mock_poll.return_value = (
        [{"sha256": "e" * 64, "_ti_artifact": "e" * 64, "discovery_source": "intel_threatingestor"}],
        {"candidates": 1, "seen": 1},
    )
    collector = ThreatIntelCollector(tracker=tmp_paths["tracker"])

    raw, stats = collector.poll_threatingestor_artifacts(batch_size=10)

    assert len(raw) == 1
    assert stats["candidates"] == 1
    mock_poll.assert_called_once()


@patch("src.intel.collector.mb.is_pe_hash", return_value=False)
def test_validate_rejects_non_pe_on_mb(mock_pe, steady_collector):
    collector = steady_collector
    sha = "b" * 64
    stats = collector.validate_and_queue(
        [{"sha256": sha, "source_id": 1}],
        use_semantic_filter=False,
    )
    assert stats["rejected"] == 1
    assert stats["not_pe"] == 1
    assert collector.tracker.fetch_pending_hashes() == []

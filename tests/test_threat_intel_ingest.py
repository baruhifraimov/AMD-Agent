"""Tests for threat intel ingest graph node."""

from unittest.mock import patch

from src.collection.context import CollectionContext
from src.nodes.threat_intel_ingest import threat_intel_ingest
from src.sources.base import SampleCandidate
from src.state import AgentState


def _steady_ctx() -> CollectionContext:
    return CollectionContext(
        benign_count=100,
        malware_count=100,
        model_ready=True,
        pending_depth=0,
    )


def _pending_candidate(sha: str) -> dict:
    return {
        "external_id": sha,
        "provider": "malwarebazaar",
        "expected_label": 1,
        "download_ref": {"sha256": sha},
        "metadata": {"discovery_source": "intel_rss"},
    }


def _sample_candidate(sha: str, provider: str = "malwarebazaar") -> SampleCandidate:
    return SampleCandidate(
        external_id=sha,
        provider=provider,
        expected_label=1,
        download_ref={"sha256": sha},
        metadata={"discovery_source": provider},
    )


@patch("src.nodes.threat_intel_ingest.INTEL_INGEST_ENABLED", False)
def test_ingest_empty_when_disabled():
    out = threat_intel_ingest(AgentState())
    assert out["sample_candidates"] == []


@patch("src.nodes.threat_intel_ingest.discover_with_fallback", return_value=[])
@patch("src.nodes.threat_intel_ingest.build_collection_context", return_value=_steady_ctx())
@patch("src.nodes.threat_intel_ingest.ThreatIntelCollector")
def test_ingest_merges_threatingestor_and_native(mock_cls, _mock_ctx, mock_fill, tmp_paths):
    mock_coll = mock_cls.return_value
    mock_coll.sources.count_enabled.return_value = 1
    mock_coll.seed_curated_sources.return_value = {"enabled": 1, "seeded": 0}
    mock_coll.discover_sources.return_value = {"upserted": 0}
    mock_coll.poll_threatingestor_artifacts.return_value = (
        [{"sha256": "a" * 64, "discovery_source": "intel_threatingestor"}],
        {"candidates": 1},
    )
    mock_coll.poll_due_feeds.return_value = [{"sha256": "b" * 64, "discovery_source": "intel_rss"}]
    mock_coll.last_native_poll_stats = {
        "sources_polled": 1,
        "sources_disabled": 0,
        "entries": 1,
        "raw_hashes": 1,
        "raw_pe_urls": 0,
        "returned": 1,
    }
    mock_coll.validate_and_queue.return_value = {"queued": 1}
    mock_coll.pending_to_candidates.return_value = []
    mock_coll.sources.all_sources.return_value = []

    out = threat_intel_ingest(AgentState())
    assert out["intel_poll_stats"]["threatingestor"]["candidates"] == 1
    assert out["intel_poll_stats"]["poll_count"] == 2
    mock_coll.validate_and_queue.assert_called_once()
    merged = mock_coll.validate_and_queue.call_args[0][0]
    assert len(merged) == 2


@patch("src.nodes.threat_intel_ingest.discover_with_fallback", return_value=[])
@patch("src.nodes.threat_intel_ingest.build_collection_context", return_value=_steady_ctx())
@patch("src.nodes.threat_intel_ingest.ThreatIntelCollector")
def test_ingest_loads_pending_candidates(mock_cls, _mock_ctx, _mock_fill, tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "f" * 64
    tracker.insert_pending_hash(sha, "2024-03-01 12:00:00")

    mock_coll = mock_cls.return_value
    mock_coll.sources.count_enabled.return_value = 1
    mock_coll.seed_curated_sources.return_value = {"enabled": 1, "seeded": 0}
    mock_coll.discover_sources.return_value = {"upserted": 0}
    mock_coll.poll_threatingestor_artifacts.return_value = ([], {"candidates": 0})
    mock_coll.poll_due_feeds.return_value = []
    mock_coll.last_native_poll_stats = {
        "sources_polled": 0,
        "sources_disabled": 0,
        "entries": 0,
        "raw_hashes": 0,
        "raw_pe_urls": 0,
        "returned": 0,
    }
    mock_coll.validate_and_queue.return_value = {"queued": 0}
    mock_coll.pending_to_candidates.return_value = [_pending_candidate(sha)]
    mock_coll.sources.all_sources.return_value = []

    out = threat_intel_ingest(AgentState())
    assert len(out["sample_candidates"]) == 1
    assert out["sample_candidates"][0]["download_ref"]["sha256"] == sha


@patch("src.nodes.threat_intel_ingest.PE_FETCH_LIMIT", 10)
@patch("src.nodes.threat_intel_ingest.build_collection_context", return_value=_steady_ctx())
@patch("src.nodes.threat_intel_ingest.ThreatIntelCollector")
@patch("src.nodes.threat_intel_ingest.discover_with_fallback")
def test_ingest_volume_fill_completes_underfilled_cti_batch(
    mock_fill,
    mock_cls,
    _mock_ctx,
    tmp_paths,
):
    mock_coll = mock_cls.return_value
    mock_coll.sources.count_enabled.return_value = 1
    mock_coll.seed_curated_sources.return_value = {"enabled": 1, "seeded": 0}
    mock_coll.poll_threatingestor_artifacts.return_value = ([], {"candidates": 0})
    mock_coll.poll_due_feeds.return_value = []
    mock_coll.last_native_poll_stats = {}
    mock_coll.pending_to_candidates.return_value = [
        _pending_candidate(f"{idx:064x}") for idx in range(1, 7)
    ]
    mock_coll.sources.all_sources.return_value = []
    mock_fill.return_value = [_sample_candidate(f"{idx:064x}") for idx in range(7, 11)]

    out = threat_intel_ingest(AgentState())

    assert len(out["sample_candidates"]) == 10
    assert out["intel_poll_stats"]["volume_fill"]["requested"] == 4
    assert out["intel_poll_stats"]["volume_fill"]["returned"] == 4
    mock_fill.assert_called_once()
    assert mock_fill.call_args.kwargs["limit"] == 4
    assert mock_fill.call_args.args[0] == ["malwarebazaar"]


@patch("src.nodes.threat_intel_ingest.PE_FETCH_LIMIT", 10)
@patch("src.nodes.threat_intel_ingest.build_collection_context", return_value=_steady_ctx())
@patch("src.nodes.threat_intel_ingest.ThreatIntelCollector")
@patch("src.nodes.threat_intel_ingest.discover_with_fallback")
def test_ingest_volume_fill_skipped_when_cti_batch_is_full(
    mock_fill,
    mock_cls,
    _mock_ctx,
    tmp_paths,
):
    mock_coll = mock_cls.return_value
    mock_coll.sources.count_enabled.return_value = 1
    mock_coll.seed_curated_sources.return_value = {"enabled": 1, "seeded": 0}
    mock_coll.poll_threatingestor_artifacts.return_value = ([], {"candidates": 0})
    mock_coll.poll_due_feeds.return_value = []
    mock_coll.last_native_poll_stats = {}
    mock_coll.pending_to_candidates.return_value = [
        _pending_candidate(f"{idx:064x}") for idx in range(1, 11)
    ]
    mock_coll.sources.all_sources.return_value = []

    out = threat_intel_ingest(AgentState())

    assert len(out["sample_candidates"]) == 10
    assert out["intel_poll_stats"]["volume_fill"]["requested"] == 0
    assert out["intel_poll_stats"]["volume_fill"]["returned"] == 0
    mock_fill.assert_not_called()


@patch("src.nodes.threat_intel_ingest.PE_FETCH_LIMIT", 10)
@patch("src.nodes.threat_intel_ingest.build_collection_context", return_value=_steady_ctx())
@patch("src.nodes.threat_intel_ingest.ThreatIntelCollector")
@patch("src.nodes.threat_intel_ingest.discover_with_fallback")
def test_ingest_volume_fill_supplies_empty_cti_batch(
    mock_fill,
    mock_cls,
    _mock_ctx,
    tmp_paths,
):
    mock_coll = mock_cls.return_value
    mock_coll.sources.count_enabled.return_value = 1
    mock_coll.seed_curated_sources.return_value = {"enabled": 1, "seeded": 0}
    mock_coll.poll_threatingestor_artifacts.return_value = ([], {"candidates": 0})
    mock_coll.poll_due_feeds.return_value = []
    mock_coll.last_native_poll_stats = {}
    mock_coll.pending_to_candidates.return_value = []
    mock_coll.sources.all_sources.return_value = []
    mock_fill.return_value = [_sample_candidate(f"{idx:064x}") for idx in range(1, 11)]

    out = threat_intel_ingest(AgentState())

    assert len(out["sample_candidates"]) == 10
    assert out["intel_poll_stats"]["volume_fill"]["requested"] == 10
    assert out["intel_poll_stats"]["volume_fill"]["returned"] == 10
    mock_fill.assert_called_once()


@patch("src.nodes.threat_intel_ingest.INTEL_INGEST_ENABLED", True)
def test_ingest_skipped_during_bootstrap(tmp_paths):
    out = threat_intel_ingest(AgentState())
    assert out["sample_candidates"] == []
    assert out["intel_poll_stats"].get("skipped") == "bootstrap"

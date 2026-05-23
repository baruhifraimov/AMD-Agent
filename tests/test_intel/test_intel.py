"""Threat intel collector, source store, seeding, and feed validation."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.intel.collector import ThreatIntelCollector
from src.intel.feed_discovery import is_low_signal_cti_url, is_precise_intel_source_url
from src.intel.rss import is_valid_feed_url
from src.intel.seed_sources import CURATED_INTEL_SOURCES, seed_curated_sources
from src.intel.source_store import IntelSourceStore
from src.tools import threat_intel_tools as ti_tools


@pytest.fixture
def steady_collector(tmp_paths):
    with patch("src.collection.context.build_collection_context") as mock_build:
        ctx = MagicMock()
        ctx.phase = "steady"
        mock_build.return_value = ctx
        yield ThreatIntelCollector(tracker=tmp_paths["tracker"])


def test_validate_rejects_invalid_sha(steady_collector):
    stats = steady_collector.validate_and_queue(
        [{"sha256": "not-a-hash", "source_id": 1}],
        use_semantic_filter=False,
    )
    assert stats["invalid_format"] == 1 and stats["queued"] == 0


@patch("src.intel.collector.mb.is_pe_hash", return_value=True)
def test_validate_queues_pe_hash(mock_pe, steady_collector):
    sha = "a" * 64
    stats = steady_collector.validate_and_queue(
        [{"sha256": sha, "source_id": 1, "context": "malware trojan PE"}],
        use_semantic_filter=False,
    )
    assert stats["queued"] == 1
    assert steady_collector.tracker.fetch_pending_hashes()[0]["sha256"] == sha


def test_intel_source_store_upsert_and_disable(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)
    sid = store.upsert_source("https://example.com/feed/", source_type="rss")
    store.disable_source(sid)
    assert int(store.get_source(sid)["enabled"]) == 0


def test_seed_curated_sources_upserts_known_feeds(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)
    stats = seed_curated_sources(store)
    assert stats["seeded"] == len(CURATED_INTEL_SOURCES)
    urls = {s["url"] for s in store.all_sources()}
    assert "https://thedfirreport.com/feed/" in urls


def test_feed_discovery_and_rss_validation():
    assert is_low_signal_cti_url("https://arxiv.org/abs/2505.24231")
    assert is_precise_intel_source_url("https://thedfirreport.com/feed/")
    assert is_valid_feed_url("https://example.com/rss.xml")
    assert not is_valid_feed_url("https://example.com/blog/post")


@patch("src.tools.threat_intel_tools._collector")
def test_validate_and_queue_tool(mock_coll):
    mock_coll.return_value.validate_and_queue.return_value = {"queued": 1}
    payload = json.dumps({"candidates": [{"sha256": "c" * 64}]})
    assert json.loads(ti_tools.validate_and_queue_candidates(payload))["queued"] == 1

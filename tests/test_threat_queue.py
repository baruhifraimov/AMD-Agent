"""Tests for ThreatIngestor queue node."""

from src.nodes.threat_queue import consume_threatingestor_queue
from src.state import AgentState


def test_consume_empty_queue(tmp_paths):
    out = consume_threatingestor_queue(AgentState())
    assert out["sample_candidates"] == []


def test_consume_pending_hashes(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "d" * 64
    tracker.insert_pending_hash(sha, "2024-02-01 12:00:00")
    out = consume_threatingestor_queue(AgentState())
    assert len(out["sample_candidates"]) == 1
    assert out["source_type"] == "malwarebazaar"
    assert out["expected_label"] == 1
    cand = out["sample_candidates"][0]
    assert cand["download_ref"]["sha256"] == sha
    assert cand["metadata"]["discovery_source"] == "threatingestor"


def test_consume_skips_corrupted_hashes(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "e" * 64
    tracker.insert_pending_hash(sha, "2024-02-01 12:00:00")
    tracker.mark_corrupted(sha, "bad PE")
    out = consume_threatingestor_queue(AgentState())
    assert out["sample_candidates"] == []

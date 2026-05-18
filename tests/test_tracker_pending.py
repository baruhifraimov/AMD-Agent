"""Tests for ThreatIngestor pending-hash DB operations."""

from src.db.tracker import MalwareTracker


def test_fetch_pending_hashes(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "a" * 64
    tracker.insert_pending_hash(sha, "2024-01-01 00:00:00")
    pending = tracker.fetch_pending_hashes(limit=10)
    assert len(pending) == 1
    assert pending[0]["sha256"] == sha


def test_is_downloaded_vs_pending(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "b" * 64
    tracker.insert_pending_hash(sha)
    assert tracker.is_pending(sha)
    assert not tracker.is_downloaded(sha)
    tracker.update_file_path(sha, "/tmp/sandbox/fake.bin")
    assert tracker.is_downloaded(sha)
    assert not tracker.is_pending(sha)


def test_insert_pending_hash_idempotent(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "c" * 64
    tracker.insert_pending_hash(sha, "2024-01-01")
    tracker.insert_pending_hash(sha, "2024-06-01")
    pending = tracker.fetch_pending_hashes()
    assert len(pending) == 1
    assert pending[0]["acquired_at"] == "2024-01-01"

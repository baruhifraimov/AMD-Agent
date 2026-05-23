"""Tests for pending-hash DB operations."""

import sqlite3

from src import config
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


def test_mark_corrupted_removes_from_pending_queue(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "f" * 64
    tracker.insert_pending_hash(sha, "2024-01-01")
    tracker.mark_corrupted(sha, "pefile parse failed")
    assert tracker.fetch_pending_hashes() == []
    row = next(r for r in tracker.fetch_chronological() if r["sha256"] == sha)
    assert row["status"] == "corrupted"
    assert row["reject_reason"] == "pefile parse failed"


def test_tracker_uses_wal_journal_mode(tmp_paths):
    db_path = tmp_paths["db"]
    MalwareTracker(db_path)
    with sqlite3.connect(db_path) as conn:
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert journal_mode == "wal"


def test_provider_run_stats_and_cooldown(tmp_paths, monkeypatch):
    tracker = tmp_paths["tracker"]
    monkeypatch.setattr(config, "PROVIDER_COOLDOWN_ZERO_RUNS", 3)
    monkeypatch.setattr(config, "PROVIDER_COOLDOWN_MIN_ATTEMPTS", 5)
    monkeypatch.setattr(config, "PROVIDER_COOLDOWN_SECONDS", 43200)

    for _ in range(3):
        tracker.record_provider_run(
            provider="github",
            label=0,
            phase="steady",
            requested=10,
            discovered=10,
            returned=5,
            download_attempted=5,
            feature_extracted=0,
        )

    stats = tracker.provider_recent_stats("github", 0)
    assert stats["runs"] == 3
    assert stats["download_attempted"] == 15
    assert tracker.is_provider_cooled_down("github", 0) is True


def test_candidate_tracking(tmp_paths):
    tracker = tmp_paths["tracker"]
    tracker.record_candidate_seen(
        candidate_key="github:https://example.com/a.exe",
        provider="github",
        label=0,
        external_id="https://example.com/a.exe",
        source_url="https://example.com/a.exe",
        status="seen",
    )
    tracker.record_candidate_outcome(
        "github:https://example.com/a.exe",
        status="downloaded",
        sha256="d" * 64,
        increment_attempts=True,
    )
    with sqlite3.connect(tmp_paths["db"]) as conn:
        row = conn.execute(
            "SELECT status, attempts, sha256 FROM candidates WHERE candidate_key = ?",
            ("github:https://example.com/a.exe",),
        ).fetchone()
    assert row == ("downloaded", 1, "d" * 64)

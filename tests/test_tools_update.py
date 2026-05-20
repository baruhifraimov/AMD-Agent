"""Tests for Update tool wrappers."""

from src.config import FEATURE_NAMES
from src.tools import update as update_tool


def _features(seed: int) -> dict:
    return {name: float(seed) for name in FEATURE_NAMES}


def test_insert_sample_and_update_features(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "a" * 64
    update_tool.insert_sample(tracker, sha, "/tmp/a.bin", "2024-01-01", label=1)
    update_tool.update_features(tracker, sha, _features(1))
    row = tracker.get_sample(sha)
    assert row is not None
    assert row["features"] is not None


def test_update_file_path_for_pending(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "b" * 64
    update_tool.insert_pending_hash(tracker, sha, label=1)
    update_tool.update_file_path(tracker, sha, "/tmp/b.bin")
    assert tracker.is_downloaded(sha)


def test_update_prediction(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "c" * 64
    update_tool.insert_sample(
        tracker,
        sha,
        "/tmp/c.bin",
        "2024-01-01",
        features=_features(2),
        label=0,
    )
    update_tool.update_prediction(tracker, sha, 0.42)
    row = tracker.get_sample(sha)
    assert row is not None
    assert abs(float(row["prediction"]) - 0.42) < 1e-6


def test_mark_corrupted(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "d" * 64
    update_tool.mark_corrupted(tracker, sha, "test reason", label=1)
    assert tracker.is_corrupted(sha)

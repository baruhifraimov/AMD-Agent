"""Integration tests for pipeline nodes."""

from unittest.mock import MagicMock, patch

from src.nodes.data_validation import data_validation
from src.nodes.drift_monitor import drift_monitor
from src.nodes.feature_extraction import feature_extraction
from src.nodes.active_learning_explain import active_learning_explain
from src.state import AgentState


def test_data_validation_filters_non_mz(tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    state = AgentState(
        downloaded_paths=[str(minimal_pe_path.path)],
        discovered_hashes=[sha],
        expected_label=0,
        hash_metadata={sha: {"first_seen": "2024-01-01 00:00:00", "expected_label": 0}},
    )
    out = data_validation(state)
    assert len(out["downloaded_paths"]) == 1


def test_data_validation_malware_label(tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    state = AgentState(
        downloaded_paths=[str(minimal_pe_path.path)],
        discovered_hashes=[sha],
        expected_label=1,
        hash_metadata={sha: {"first_seen": "2024-01-01 00:00:00"}},
    )
    out = data_validation(state)
    assert len(out["downloaded_paths"]) == 1
    rows = tmp_paths["tracker"].fetch_chronological()
    assert any(r["sha256"] == sha and r["label"] == 1 for r in rows)


def test_data_validation_updates_pending_row(tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    tracker = tmp_paths["tracker"]
    tracker.insert_pending_hash(sha, "2024-01-01 00:00:00")
    state = AgentState(
        downloaded_paths=[str(minimal_pe_path.path)],
        expected_label=1,
        hash_metadata={sha: {"first_seen": "2024-01-01 00:00:00", "expected_label": 1}},
    )
    out = data_validation(state)
    assert len(out["downloaded_paths"]) == 1
    rows = tracker.fetch_chronological()
    row = next(r for r in rows if r["sha256"] == sha)
    assert row["file_path"] == str(minimal_pe_path.path)
    assert row["acquired_at"] == "2024-01-01 00:00:00"


def test_drift_monitor_no_drift(tmp_paths):
    state = AgentState(
        feature_vectors=[{"sha256": "a" * 64, "avg_section_entropy": 0.5}],
        section_entropies=[0.5],
    )
    out = drift_monitor(state)
    assert out["drift_detected"] is False


def test_active_learning_stub():
    state = AgentState(drift_detected=True, new_labeled_batch=[{"label": 1}])
    out = active_learning_explain(state)
    assert "Drift detected" in out["semantic_report"]


@patch("src.nodes.feature_extraction.extract_pe_features")
def test_feature_extraction(mock_extract, tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    mock_extract.return_value = {
        "avg_section_entropy": 1.0,
        "sha256": sha,
    }
    state = AgentState(downloaded_paths=[str(minimal_pe_path.path)])
    out = feature_extraction(state)
    assert len(out["feature_vectors"]) == 1

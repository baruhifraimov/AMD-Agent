"""Pipeline node smoke tests — one happy path and one failure per concern."""

from unittest.mock import MagicMock, patch

from src.nodes.binary_fetch import binary_fetch
from src.nodes.classifier_inference import classifier_inference
from src.nodes.data_validation import data_validation
from src.nodes.drift_monitor import drift_monitor
from src.nodes.explain_drift_context import explain_drift_context
from src.nodes.feature_extraction import feature_extraction
from src.nodes.source_discovery import source_discovery
from src.nodes.source_selector import source_selector
from src.sources.base import SampleCandidate
from src.state import AgentState


def test_data_validation_accepts_labeled_pe(tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    out = data_validation(
        AgentState(
            downloaded_paths=[str(minimal_pe_path.path)],
            expected_label=1,
            hash_metadata={sha: {"first_seen": "2024-01-01 00:00:00", "expected_label": 1}},
        )
    )
    assert len(out["downloaded_paths"]) == 1
    assert tmp_paths["tracker"].get_sample(sha)["label"] == 1


def test_data_validation_rejects_invalid_pe(tmp_paths):
    import hashlib

    content = b"MZ" + b"\x00" * 128
    sha = hashlib.sha256(content).hexdigest()
    path = tmp_paths["sandbox"] / f"{sha}.bin"
    path.write_bytes(content)
    out = data_validation(AgentState(downloaded_paths=[str(path)]))
    assert out["downloaded_paths"] == []
    row = next(r for r in tmp_paths["tracker"].fetch_chronological() if r["sha256"] == sha)
    assert row["status"] == "corrupted"


@patch("src.nodes.explain_drift_context.ollama_drift_context_report_enabled", return_value=True)
@patch("src.nodes.explain_drift_context.summarize_drift_context")
def test_explain_drift_context(mock_summarize, _mock_flag):
    mock_summarize.return_value = "Drift summary."
    out = explain_drift_context(
        AgentState(drift_detected=True, drift_stats={"mean_shift": 1.0, "corr_shift": 0.3})
    )
    mock_summarize.assert_called_once()
    assert out["semantic_report"] == "Drift summary."


@patch("src.nodes.explain_drift_context.ollama_drift_context_report_enabled", return_value=False)
@patch("src.nodes.explain_drift_context.summarize_drift_context")
def test_explain_drift_context_skipped_when_disabled(mock_summarize, _mock_flag):
    out = explain_drift_context(
        AgentState(drift_detected=True, drift_stats={"mean_shift": 1.0, "corr_shift": 0.3})
    )
    mock_summarize.assert_not_called()
    assert out["semantic_report"] is None


def test_drift_monitor_skips_bootstrap():
    out = drift_monitor(AgentState(collection_phase="bootstrap", feature_vectors=[{"sha256": "a" * 64}]))
    assert out["drift_detected"] is False
    assert out["pending_drift_log"] is False


def test_drift_monitor_no_drift_on_small_batch(tmp_paths):
    state = AgentState(
        feature_vectors=[{"sha256": "a" * 64, "avg_section_entropy": 0.5}],
        section_entropies=[0.5],
    )
    assert drift_monitor(state)["drift_detected"] is False


@patch("src.nodes.classifier_inference.record_model_update_comparison")
@patch("src.nodes.classifier_inference.score_samples", return_value={})
@patch("src.nodes.classifier_inference.cold_start_train")
@patch("src.nodes.classifier_inference.load_bundle", return_value=None)
def test_classifier_inference_records_cold_start_baseline(
    _load_bundle, mock_cold_start, _score_samples, mock_record, tmp_paths
):
    mock_cold_start.return_value = {"threshold": 0.5, "model_version": "v_start"}
    out = classifier_inference(AgentState())
    mock_record.assert_called_once()
    assert out["evaluation_metrics"]["model_ready"] == 1.0


@patch("src.nodes.binary_fetch.download_pe_candidate")
def test_binary_fetch_downloads_candidates(mock_download, tmp_paths):
    mock_download.side_effect = [b"MZ" + b"\x00" * 64, b"MZ" + b"\x01" * 64]
    with patch("src.nodes.binary_fetch.ThreatIntelCollector") as mock_intel:
        mock_intel.return_value.record_download_outcome.return_value = None
        out = binary_fetch(
            AgentState(
                sample_candidates=[
                    SampleCandidate("a", "sysinternals", 0, {"url": "https://example.com/a.exe"}).to_dict(),
                    SampleCandidate("b", "github", 0, {"url": "https://example.com/b.exe"}).to_dict(),
                ]
            )
        )
    assert len(out["downloaded_paths"]) == 2


@patch("src.nodes.binary_fetch.download_pe_candidate")
def test_binary_fetch_skips_known_sha(mock_download, tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    tmp_paths["tracker"].insert_sample(sha, str(minimal_pe_path.path), "2024-01-01", label=1)
    out = binary_fetch(
        AgentState(sample_candidates=[SampleCandidate(sha, "malwarebazaar", 1, {"sha256": sha}).to_dict()])
    )
    assert out["downloaded_paths"] == []
    mock_download.assert_not_called()


@patch("src.nodes.source_discovery.discover_active_benign_sources")
def test_source_discovery_benign(mock_discover):
    mock_discover.return_value = [
        SampleCandidate("a", "sysinternals", 0, {"url": "https://example.com/a.exe"}),
    ]
    out = source_discovery(AgentState(selected_sources=["sysinternals"], expected_label=0))
    assert len(out["sample_candidates"]) == 1


@patch("src.nodes.source_selector.choose_sources_with_ollama", return_value=None)
@patch("src.nodes.source_selector.CollectionStrategyFactory")
def test_source_selector_factory_fallback(mock_factory, _mock_ollama, tmp_paths):
    from src.collection.strategies.base import SourceSelectionResult

    mock_strategy = MagicMock()
    mock_strategy.select.return_value = SourceSelectionResult(
        source_type="malwarebazaar",
        selected_sources=["malwarebazaar"],
        expected_label=1,
        discovery_strategy="bootstrap_fast_path",
        collection_phase="bootstrap",
    )
    mock_factory.create.return_value = mock_strategy
    out = source_selector(AgentState())
    assert out["source_type"] == "malwarebazaar"


@patch("src.nodes.feature_extraction.extract_pe_features_with_error")
def test_feature_extraction_persists_features(mock_extract, tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    tracker = tmp_paths["tracker"]
    tracker.insert_sample(sha, str(minimal_pe_path.path), "2024-01-01", label=1)
    mock_extract.return_value = ({"avg_section_entropy": 1.0, "sha256": sha}, None)
    out = feature_extraction(
        AgentState(
            downloaded_paths=[str(minimal_pe_path.path)],
            hash_metadata={sha: {"expected_label": 1}},
        )
    )
    assert len(out["feature_vectors"]) == 1
    row = tracker.get_sample(sha)
    assert row is not None and row.get("features") is not None


@patch("src.nodes.feature_extraction.triage_pe_error", return_value="reject")
@patch("src.nodes.feature_extraction.extract_pe_features_with_error")
def test_feature_extraction_marks_corrupted(mock_extract, _triage, tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    tracker = tmp_paths["tracker"]
    tracker.insert_pending_hash(sha, "2024-01-01 00:00:00")
    tracker.update_file_path(sha, str(minimal_pe_path.path))
    mock_extract.return_value = (None, "Unable to parse PE header")
    out = feature_extraction(
        AgentState(
            downloaded_paths=[str(minimal_pe_path.path)],
            hash_metadata={sha: {"expected_label": 1}},
        )
    )
    assert out["downloaded_paths"] == []
    row = next(r for r in tracker.fetch_chronological() if r["sha256"] == sha)
    assert row["status"] == "corrupted"

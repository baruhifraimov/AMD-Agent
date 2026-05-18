"""Integration tests for pipeline nodes."""

from unittest.mock import MagicMock, patch

from src.nodes.data_validation import data_validation
from src.nodes.drift_monitor import drift_monitor
from src.nodes.feature_extraction import feature_extraction
from src.nodes.active_learning_explain import active_learning_explain
from src.nodes.binary_fetch import binary_fetch
from src.nodes.source_selector import source_selector
from src.nodes.source_discovery import source_discovery
from src.sources.base import SampleCandidate
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


def test_data_validation_rejects_missing_pe_signature(tmp_paths, minimal_pe_path):
    import hashlib

    content = b"MZ" + b"\x00" * 128
    sha = hashlib.sha256(content).hexdigest()
    path = tmp_paths["sandbox"] / f"{sha}.bin"
    path.write_bytes(content)

    out = data_validation(AgentState(downloaded_paths=[str(path)]))

    assert out["downloaded_paths"] == []
    row = next(r for r in tmp_paths["tracker"].fetch_chronological() if r["sha256"] == sha)
    assert row["status"] == "corrupted"
    assert row["reject_reason"] == "PE signature check failed"


def test_data_validation_rejects_sha_filename_mismatch(tmp_paths, minimal_pe_path):
    wrong_sha = "0" * 64
    wrong_path = tmp_paths["sandbox"] / f"{wrong_sha}.bin"
    wrong_path.write_bytes(minimal_pe_path.path.read_bytes())

    out = data_validation(AgentState(downloaded_paths=[str(wrong_path)]))

    assert out["downloaded_paths"] == []
    row = next(r for r in tmp_paths["tracker"].fetch_chronological() if r["sha256"] == wrong_sha)
    assert row["status"] == "corrupted"
    assert "SHA256 filename mismatch" in row["reject_reason"]


def test_data_validation_skips_corrupted_hash(tmp_paths, minimal_pe_path):
    tracker = tmp_paths["tracker"]
    tracker.mark_corrupted(minimal_pe_path.sha256, "previous reject", file_path=str(minimal_pe_path.path))

    out = data_validation(AgentState(downloaded_paths=[str(minimal_pe_path.path)]))

    assert out["downloaded_paths"] == []


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


@patch("src.nodes.active_learning_explain.subprocess.run")
def test_active_learning_runs_capa_with_rules(mock_run, minimal_pe_path):
    completed = MagicMock()
    completed.returncode = 0
    completed.stdout = '{"rules": {"create process": {}}, "meta": {}}'
    completed.stderr = ""
    mock_run.return_value = completed

    out = active_learning_explain(
        AgentState(
            drift_detected=True,
            downloaded_paths=[str(minimal_pe_path.path)],
            feature_vectors=[{"sha256": minimal_pe_path.sha256, "avg_section_entropy": 7.0}],
        )
    )

    command = mock_run.call_args.args[0]
    assert "-j" in command
    assert "-r" in command
    assert str(minimal_pe_path.path) in command
    assert minimal_pe_path.sha256 in out["capa_results"]


@patch("src.nodes.binary_fetch.get_registry")
def test_binary_fetch_uses_candidate_provider(mock_registry, tmp_paths):
    provider_a = MagicMock()
    provider_b = MagicMock()
    provider_a.download.return_value = b"MZprovider-a"
    provider_b.download.return_value = b"MZprovider-b"
    registry = MagicMock()
    registry.get.side_effect = lambda name: {"sysinternals": provider_a, "github": provider_b}[name]
    mock_registry.return_value = registry

    candidates = [
        SampleCandidate("a", "sysinternals", 0, {"url": "https://example.com/a.exe"}).to_dict(),
        SampleCandidate("b", "github", 0, {"url": "https://example.com/b.exe"}).to_dict(),
    ]
    out = binary_fetch(AgentState(sample_candidates=candidates, source_type="malwarebazaar"))

    assert len(out["downloaded_paths"]) == 2
    provider_a.download.assert_called_once()
    provider_b.download.assert_called_once()


@patch("src.nodes.source_discovery.get_registry")
def test_source_discovery_uses_selected_sources(mock_registry):
    provider_a = MagicMock()
    provider_b = MagicMock()
    provider_a.name = "sysinternals"
    provider_b.name = "github"
    provider_a.expected_label = 0
    provider_b.expected_label = 0
    provider_a.discover.return_value = [
        SampleCandidate("a", "sysinternals", 0, {"url": "https://example.com/a.exe"})
    ]
    provider_b.discover.return_value = [
        SampleCandidate("b", "github", 0, {"url": "https://example.com/b.exe"})
    ]
    registry = MagicMock()
    registry.get.side_effect = lambda name: {"sysinternals": provider_a, "github": provider_b}[name]
    mock_registry.return_value = registry

    out = source_discovery(AgentState(selected_sources=["sysinternals", "github"], expected_label=0))

    assert [c["provider"] for c in out["sample_candidates"]] == ["sysinternals", "github"]


@patch("src.nodes.source_selector.choose_sources_with_ollama", return_value=None)
@patch("src.nodes.source_selector.choose_provider")
def test_source_selector_falls_back_when_ollama_unavailable(mock_choose, mock_ollama, tmp_paths):
    provider = MagicMock()
    provider.name = "malwarebazaar"
    provider.expected_label = 1
    mock_choose.return_value = provider

    out = source_selector(AgentState())

    assert out["source_type"] == "malwarebazaar"
    assert out["selected_sources"] == ["malwarebazaar"]
    assert out["discovery_strategy"] == "deterministic_fallback"


@patch("src.nodes.feature_extraction.extract_pe_features_with_error")
def test_feature_extraction(mock_extract, tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    mock_extract.return_value = (
        {
            "avg_section_entropy": 1.0,
            "sha256": sha,
        },
        None,
    )
    state = AgentState(downloaded_paths=[str(minimal_pe_path.path)])
    out = feature_extraction(state)
    assert len(out["feature_vectors"]) == 1


@patch("src.nodes.feature_extraction.triage_pe_error", return_value="reject")
@patch("src.nodes.feature_extraction.extract_pe_features_with_error")
def test_feature_extraction_marks_corrupted_on_reject(
    mock_extract,
    mock_triage,
    tmp_paths,
    minimal_pe_path,
):
    sha = minimal_pe_path.sha256
    tracker = tmp_paths["tracker"]
    tracker.insert_pending_hash(sha, "2024-01-01 00:00:00")
    tracker.update_file_path(sha, str(minimal_pe_path.path))
    mock_extract.return_value = (None, "Unable to parse PE header")

    out = feature_extraction(
        AgentState(
            downloaded_paths=[str(minimal_pe_path.path)],
            hash_metadata={sha: {"first_seen": "2024-01-01 00:00:00", "expected_label": 1}},
        )
    )

    assert out["downloaded_paths"] == []
    assert out["rejected_candidates"][0]["sha256"] == sha
    rows = tracker.fetch_chronological()
    row = next(r for r in rows if r["sha256"] == sha)
    assert row["status"] == "corrupted"
    assert "Unable to parse PE header" in row["reject_reason"]

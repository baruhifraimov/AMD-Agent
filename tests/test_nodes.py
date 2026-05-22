"""Integration tests for pipeline nodes."""

from unittest.mock import MagicMock, patch

from src.nodes.data_validation import data_validation
from src.nodes.drift_monitor import drift_monitor
from src.nodes.feature_extraction import feature_extraction
from src.nodes.explain_drift_context import explain_drift_context
from src.nodes.binary_fetch import binary_fetch
from src.nodes.source_selector import source_selector
from src.nodes.source_discovery import source_discovery
from src.llm.client import SourceDecision
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
    assert out["bootstrap_metrics"]["pe_valid_count"] == 1


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


def test_data_validation_persists_source_url(tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    url = "https://example.com/tool.exe"
    state = AgentState(
        downloaded_paths=[str(minimal_pe_path.path)],
        expected_label=0,
        hash_metadata={
            sha: {
                "first_seen": "2024-01-01 00:00:00",
                "expected_label": 0,
                "source_provider": "sysinternals",
                "source_url": url,
            }
        },
    )
    out = data_validation(state)
    assert len(out["downloaded_paths"]) == 1
    row = tmp_paths["tracker"].get_sample(sha)
    assert row["source_provider"] == "sysinternals"
    assert row["source_url"] == url
    assert tmp_paths["tracker"].is_source_url_seen(url)


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


def test_explain_drift_context_stub():
    state = AgentState(drift_detected=True, new_labeled_batch=[{"label": 1}])
    out = explain_drift_context(state)
    assert "Drift detected" in out["semantic_report"]


@patch("src.nodes.explain_drift_context.subprocess.run")
def test_explain_drift_context_runs_capa_with_rules(mock_run, minimal_pe_path):
    completed = MagicMock()
    completed.returncode = 0
    completed.stdout = '{"rules": {"create process": {}}, "meta": {}}'
    completed.stderr = ""
    mock_run.return_value = completed

    out = explain_drift_context(
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


@patch("src.nodes.binary_fetch.ThreatIntelCollector")
@patch("src.nodes.binary_fetch.download_pe_candidate")
def test_binary_fetch_uses_candidate_provider(mock_download, mock_intel_cls, tmp_paths):
    mock_download.side_effect = [b"MZ" + b"\x00" * 64, b"MZ" + b"\x01" * 64]
    mock_intel_cls.return_value.record_download_outcome.return_value = None

    candidates = [
        SampleCandidate("a", "sysinternals", 0, {"url": "https://example.com/a.exe"}).to_dict(),
        SampleCandidate("b", "github", 0, {"url": "https://example.com/b.exe"}).to_dict(),
    ]
    out = binary_fetch(AgentState(sample_candidates=candidates, source_type="malwarebazaar"))

    assert len(out["downloaded_paths"]) == 2
    assert out["bootstrap_metrics"]["downloaded_count"] == 2
    assert all("source_url" in meta for meta in out["hash_metadata"].values())
    assert mock_download.call_count == 2


@patch("src.nodes.source_discovery.discover_with_fallback")
def test_source_discovery_uses_selected_sources(mock_discover, tmp_paths):
    def discover_side_effect(*args, **kwargs):
        kwargs["stats"].append(
            {
                "provider": "sysinternals",
                "discovered": 2,
                "fresh": 2,
                "returned": 2,
            }
        )
        return [
            SampleCandidate("a", "sysinternals", 0, {"url": "https://example.com/a.exe"}),
            SampleCandidate("b", "github", 0, {"url": "https://example.com/b.exe"}),
        ]

    mock_discover.side_effect = discover_side_effect

    out = source_discovery(AgentState(selected_sources=["sysinternals", "github"], expected_label=0))

    assert [c["provider"] for c in out["sample_candidates"]] == ["sysinternals", "github"]
    assert out["bootstrap_metrics"]["discovered_count"] == 2
    assert out["bootstrap_metrics"]["discovery"][0]["fresh"] == 2
    mock_discover.assert_called_once()


@patch("src.nodes.source_discovery.discover_with_fallback")
@patch("src.nodes.source_discovery.discover_active_malware_sources")
def test_source_discovery_uses_active_malware_sources_for_bootstrap_malware(
    mock_active,
    mock_fallback,
    tmp_paths,
):
    def discover_side_effect(*args, **kwargs):
        kwargs["stats"].extend(
            [
                {
                    "provider": "malwarebazaar",
                    "discovered": 1,
                    "fresh": 1,
                    "returned": 1,
                },
                {
                    "provider": "malshare",
                    "discovered": 1,
                    "fresh": 1,
                    "returned": 1,
                },
            ]
        )
        return [
            SampleCandidate("a" * 64, "malwarebazaar", 1, {"sha256": "a" * 64}),
            SampleCandidate("b" * 64, "malshare", 1, {"sha256": "b" * 64}),
        ]

    mock_active.side_effect = discover_side_effect

    out = source_discovery(AgentState(selected_sources=["malwarebazaar"], expected_label=1))

    assert [c["provider"] for c in out["sample_candidates"]] == ["malwarebazaar", "malshare"]
    assert [s["provider"] for s in out["bootstrap_metrics"]["discovery"]] == [
        "malwarebazaar",
        "malshare",
    ]
    mock_active.assert_called_once()
    mock_fallback.assert_not_called()


@patch("src.nodes.binary_fetch.download_pe_candidate")
def test_binary_fetch_skips_known_sha_before_download(mock_download, tmp_paths, minimal_pe_path):
    sha = minimal_pe_path.sha256
    tmp_paths["tracker"].insert_sample(sha, str(minimal_pe_path.path), "2024-01-01", label=1)

    out = binary_fetch(
        AgentState(
            sample_candidates=[
                SampleCandidate(
                    sha,
                    "malwarebazaar",
                    1,
                    {"sha256": sha},
                ).to_dict()
            ]
        )
    )

    assert out["downloaded_paths"] == []
    mock_download.assert_not_called()


@patch("src.nodes.source_selector.choose_sources_with_ollama", return_value=None)
@patch("src.nodes.source_selector.CollectionStrategyFactory")
def test_source_selector_falls_back_when_ollama_unavailable(mock_factory, mock_ollama, tmp_paths):
    from src.collection.strategies.base import SourceSelectionResult

    mock_selection = SourceSelectionResult(
        source_type="malwarebazaar",
        selected_sources=["malwarebazaar"],
        expected_label=1,
        discovery_strategy="bootstrap_fast_path",
        collection_phase="bootstrap",
    )
    mock_strategy = MagicMock()
    mock_strategy.select.return_value = mock_selection
    mock_factory.create.return_value = mock_strategy

    out = source_selector(AgentState())

    assert out["source_type"] == "malwarebazaar"
    assert out["selected_sources"] == ["malwarebazaar"]
    assert out["collection_phase"] == "bootstrap"


@patch(
    "src.nodes.source_selector.choose_sources_with_ollama",
    return_value=SourceDecision(
        source_type="malwarebazaar",
        selected_sources=["malwarebazaar"],
        expected_label=1,
        discovery_strategy="ollama",
    ),
)
@patch("src.nodes.source_selector.CollectionStrategyFactory")
def test_source_selector_respects_required_label_over_ollama(
    mock_factory,
    mock_ollama,
    tmp_paths,
):
    from src.collection.strategies.base import SourceSelectionResult

    mock_selection = SourceSelectionResult(
        source_type="sysinternals",
        selected_sources=["sysinternals"],
        expected_label=0,
        discovery_strategy="bootstrap_fast_path",
        collection_phase="bootstrap",
    )
    mock_strategy = MagicMock()
    mock_strategy.select.return_value = mock_selection
    mock_factory.create.return_value = mock_strategy

    out = source_selector(AgentState())

    assert out["source_type"] == "sysinternals"
    assert out["selected_sources"] == ["sysinternals"]
    assert out["expected_label"] == 0
    assert out["collection_phase"] == "bootstrap"


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
    assert out["bootstrap_metrics"]["feature_extracted_count"] == 1


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

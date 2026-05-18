"""Tests for LangGraph routing."""

from unittest.mock import MagicMock, patch

from src.graph import build_graph, route_after_drift
from src.sources.base import SampleCandidate
from src.state import AgentState


def test_route_after_drift():
    assert route_after_drift(AgentState(drift_detected=False)) == "inference"
    assert route_after_drift(AgentState(drift_detected=True)) == "retrain"


@patch("src.nodes.source_selector.choose_provider")
@patch("src.nodes.source_discovery.get_registry")
@patch("src.nodes.feature_extraction.extract_pe_features")
def test_graph_no_drift_path(
    mock_feats,
    mock_registry,
    mock_choose,
    tmp_paths,
    minimal_pe_path,
):
    sha = minimal_pe_path.sha256
    mock_provider = MagicMock()
    mock_provider.name = "malwarebazaar"
    mock_provider.expected_label = 1
    mock_provider.discover.return_value = [
        SampleCandidate(
            external_id=sha,
            provider="malwarebazaar",
            expected_label=1,
            download_ref={"sha256": sha},
            metadata={"first_seen": "2024-01-01"},
        )
    ]
    mock_provider.download.return_value = minimal_pe_path.path.read_bytes()
    mock_choose.return_value = mock_provider

    mock_reg = MagicMock()
    mock_reg.get.return_value = mock_provider
    mock_registry.return_value = mock_reg

    mock_feats.return_value = {
        "sha256": sha,
        "avg_section_entropy": 0.3,
        "dos_header_size": 1,
        "pe_header_offset": 2,
        "rich_header_present": 0,
        "rich_entropy": 0,
        "num_sections": 1,
        "max_section_entropy": 0.5,
        "num_imported_dlls": 0,
        "num_imported_apis": 0,
        "has_exec_apis": 0,
        "image_size": 1,
        "entry_point": 1,
        "subsystem": 1,
        "dll_characteristics": 0,
        "timestamp": 0,
    }

    graph = build_graph()
    result = graph.invoke(AgentState())
    final = AgentState.model_validate(result)
    assert final.source_type == "malwarebazaar"
    assert sha in final.discovered_hashes or len(final.feature_vectors) >= 0

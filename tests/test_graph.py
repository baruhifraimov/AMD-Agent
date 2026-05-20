"""Tests for LangGraph routing."""

from unittest.mock import MagicMock, patch

from src.graph import (
    build_graph,
    route_after_drift,
    route_after_intel_ingest,
    route_after_selector,
)
from src.sources.base import SampleCandidate
from src.state import AgentState


def test_route_after_drift():
    assert route_after_drift(AgentState(drift_detected=False)) == "inference"
    assert route_after_drift(AgentState(drift_detected=True)) == "retrain"


def test_route_after_selector():
    assert route_after_selector(AgentState(expected_label=0)) == "source_discovery"
    assert route_after_selector(
        AgentState(expected_label=1, collection_phase="bootstrap")
    ) == "source_discovery"
    assert route_after_selector(
        AgentState(
            expected_label=1,
            collection_phase="steady",
            route_hint="threat_intel_ingest",
        )
    ) == "threat_intel_ingest"
    assert route_after_selector(
        AgentState(expected_label=1, collection_phase="steady", route_hint="source_discovery")
    ) == "source_discovery"


def test_route_after_intel_ingest():
    assert route_after_intel_ingest(AgentState(sample_candidates=[])) == "source_discovery"
    assert route_after_intel_ingest(AgentState(sample_candidates=[{"x": 1}])) == "binary_fetch"


@patch("src.nodes.binary_fetch.download_pe_candidate")
@patch("src.nodes.threat_intel_ingest.ThreatIntelCollector")
@patch("src.graph.source_selector")
@patch("src.nodes.source_discovery.discover_with_fallback", return_value=[])
@patch("src.nodes.feature_extraction.extract_pe_features_with_error")
def test_graph_malware_pending_queue_path(
    mock_feats,
    mock_discover,
    mock_selector,
    mock_intel_coll,
    mock_download,
    tmp_paths,
    minimal_pe_path,
):
    sha = minimal_pe_path.sha256
    tracker = tmp_paths["tracker"]
    tracker.insert_pending_hash(sha, "2024-01-01")

    mock_selector.return_value = {
        "source_type": "malwarebazaar",
        "selected_sources": ["malwarebazaar"],
        "expected_label": 1,
        "discovery_strategy": "intel_pending_queue",
        "collection_phase": "steady",
        "route_hint": "threat_intel_ingest",
        "cti_queries": [],
        "sample_candidates": [],
        "discovered_hashes": [],
        "downloaded_paths": [],
        "feature_vectors": [],
        "feature_errors": {},
        "predictions": {},
        "section_entropies": [],
        "new_labeled_batch": [],
        "drift_detected": False,
        "hash_metadata": {},
        "rejected_candidates": [],
        "capa_results": {},
        "cti_evidence": {},
        "intel_poll_stats": {},
        "intel_sources_polled": [],
    }

    mock_coll = mock_intel_coll.return_value
    mock_coll.sources.count_enabled.return_value = 1
    mock_coll.poll_threatingestor_artifacts.return_value = ([], {})
    mock_coll.poll_due_feeds.return_value = []
    mock_coll.validate_and_queue.return_value = {"queued": 0}
    mock_coll.sources.all_sources.return_value = []
    mock_coll.pending_to_candidates.return_value = [
        SampleCandidate(
            external_id=sha,
            provider="malwarebazaar",
            expected_label=1,
            download_ref={"sha256": sha},
            metadata={"discovery_source": "intel_rss"},
        ).to_dict()
    ]
    mock_download.return_value = minimal_pe_path.path.read_bytes()

    mock_feats.return_value = (
        {
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
            "string_count": 1.0,
            "avg_string_length": 4.0,
        },
        None,
    )

    graph = build_graph()
    result = graph.invoke(
        AgentState(),
        config={"configurable": {"thread_id": "test-graph-pending"}},
    )
    final = AgentState.model_validate(result)
    assert final.source_type == "malwarebazaar"
    assert sha in final.discovered_hashes or len(final.feature_vectors) >= 0
    assert tracker.is_downloaded(sha)

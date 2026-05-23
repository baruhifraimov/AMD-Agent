"""Tests for LangGraph routing."""

from unittest.mock import patch

from src.graph import (
    build_graph,
    route_after_drift,
    route_after_pe_discovery,
    route_after_selector,
)
from src.sources.base import SampleCandidate
from src.state import AgentState


def test_route_after_drift():
    assert route_after_drift(AgentState(drift_detected=False)) == "inference"
    assert route_after_drift(AgentState(drift_detected=True)) == "retrain"


@patch("src.graph.build_collection_context")
def test_route_after_selector(mock_ctx):
    from src.collection.context import CollectionContext

    steady = CollectionContext(
        benign_count=100, malware_count=100, model_ready=True, pending_depth=0
    )
    bootstrap = CollectionContext(
        benign_count=50, malware_count=50, model_ready=False, pending_depth=0
    )

    mock_ctx.return_value = steady
    assert route_after_selector(AgentState(expected_label=0)) == "source_discovery"
    assert route_after_selector(
        AgentState(expected_label=1, collection_phase="bootstrap")
    ) == "source_discovery"
    assert route_after_selector(
        AgentState(
            expected_label=1,
            collection_phase="steady",
            route_hint="source_discovery",
        )
    ) == "source_discovery"
    assert route_after_selector(
        AgentState(expected_label=1, collection_phase="steady", route_hint="source_discovery")
    ) == "source_discovery"

    mock_ctx.return_value = bootstrap
    assert route_after_selector(
        AgentState(
            expected_label=1,
            collection_phase="steady",
            route_hint="source_discovery",
        )
    ) == "source_discovery"


@patch("src.graph.PE_SOURCE_DISCOVERY_ENABLED", False)
def test_route_after_selector_pe_discovery_disabled():
    from src.collection.context import CollectionContext

    with patch("src.graph.build_collection_context") as mock_ctx:
        mock_ctx.return_value = CollectionContext(
            benign_count=100, malware_count=100, model_ready=True, pending_depth=0
        )
        assert (
            route_after_selector(
                AgentState(
                    expected_label=1,
                    route_hint="source_discovery",
                    need_new_sources=True,
                )
            )
            == "source_discovery"
        )


@patch("src.graph.PE_SOURCE_DISCOVERY_ENABLED", True)
@patch("src.graph.PESourceStore")
def test_route_pe_source_discovery_when_sparse(mock_store):
    mock_store.return_value.count_active.return_value = 0
    with patch("src.graph.build_collection_context") as mock_ctx:
        from src.collection.context import CollectionContext

        mock_ctx.return_value = CollectionContext(
            benign_count=100, malware_count=100, model_ready=True, pending_depth=0
        )
        assert (
            route_after_selector(
                AgentState(expected_label=1, collection_phase="steady")
            )
            == "pe_source_discovery"
        )


def test_route_after_pe_discovery():
    assert route_after_pe_discovery(AgentState(route_hint="source_discovery")) == "source_discovery"
    assert route_after_pe_discovery(AgentState()) == "source_discovery"


@patch("src.graph._CHECKPOINTER", None)
@patch("src.nodes.evaluation_node.EVAL_EVERY_RUNS", 1)
@patch("src.evaluation.tesseract.run_tesseract_eval", return_value={})
@patch("src.evaluation.tesseract.plot_performance_decay")
@patch("src.graph.build_collection_context")
@patch("src.nodes.binary_fetch.download_pe_candidate")
@patch("src.graph.source_selector")
@patch("src.nodes.source_discovery.discover_active_malware_sources")
@patch("src.nodes.feature_extraction.extract_pe_features_with_error")
def test_graph_malware_source_discovery_path(
    mock_feats,
    mock_discover,
    mock_selector,
    mock_download,
    mock_graph_ctx,
    mock_plot,
    mock_tesseract,
    tmp_paths,
    minimal_pe_path,
):
    from src.collection.context import CollectionContext

    sha = minimal_pe_path.sha256
    tracker = tmp_paths["tracker"]
    tracker.insert_pending_hash(sha, "2024-01-01")
    steady_ctx = CollectionContext(
        benign_count=100, malware_count=100, model_ready=True, pending_depth=1
    )
    mock_graph_ctx.return_value = steady_ctx

    mock_selector.return_value = {
        "source_type": "malwarebazaar",
        "selected_sources": ["malwarebazaar"],
        "expected_label": 1,
        "discovery_strategy": "steady_malware_active",
        "collection_phase": "steady",
        "route_hint": "source_discovery",
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

    mock_discover.return_value = [
        SampleCandidate(
            external_id=sha,
            provider="malwarebazaar",
            expected_label=1,
            download_ref={"sha256": sha},
            metadata={"discovery_source": "intel_rss"},
        )
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
    mock_discover.assert_called_once()
    mock_tesseract.assert_called_once()


def test_build_graph_includes_evaluation_node():
    graph = build_graph()
    node_names = set(graph.get_graph().nodes.keys())
    assert "evaluation" in node_names
